from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
import struct
from threading import RLock
from typing import Any, Iterable, Literal, Optional

from .errors import (KoutenError, ConnectionException, ProtocolException,
                     ServerException, IndeterminateWriteException)
from .transport import Connection, MAX_FRAME, expect, number

PayloadCodec = Literal["raw", "json", "nif", "bif"]


def _codec(value: str) -> PayloadCodec:
    if value not in ("raw", "json", "nif", "bif"):
        raise ValueError("Unsupported payload codec")
    return value  # type: ignore[return-value]


@dataclass(frozen=True)
class KoutenId:
    parent: int
    epoch: int
    seq: int
    t_write: float
    period: float
    head: float

    def __post_init__(self):
        for value, bits in [(self.parent, 64), (self.epoch, 32), (self.seq, 32)]:
            if type(value) is not int or not 0 <= value < (1 << bits):
                raise ValueError("ID integer out of range")
        if not all(math.isfinite(v) for v in (self.t_write, self.period, self.head)) or self.period <= 0:
            raise ValueError("Invalid ID coordinates")

    @classmethod
    def parse(cls, text: str) -> "KoutenId":
        parts = text.split(":")
        if len(parts) != 6:
            raise ValueError("KoutenId requires six fields")
        if not all(re.fullmatch(r"[0-9]+", v) for v in parts[:3]):
            raise ValueError("Invalid ID integer")
        if not all(re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", v, re.ASCII) for v in parts[3:]):
            raise ValueError("Invalid ID coordinate")
        return cls(*(int(v) for v in parts[:3]), *(float(v) for v in parts[3:]))

    def __str__(self) -> str:
        return f"{self.parent}:{self.epoch}:{self.seq}:{self.t_write}:{self.period}:{self.head}"


@dataclass(frozen=True)
class EncodedPayload:
    payload: bytes
    codec: PayloadCodec


def _parse_peers(peers: str | Iterable[str]) -> list[tuple[str, int]]:
    values = peers.split(",") if isinstance(peers, str) else list(peers)
    if not 1 <= len(values) <= 64:
        raise ValueError("Provide 1..64 ordered peers")
    result = []
    for value in values:
        match = re.fullmatch(r"(?:([a-zA-Z0-9._-]+)|\[([a-fA-F0-9:]+)\]):([0-9]{1,5})", value)
        if not match or not 1 <= int(match[3]) <= 65535:
            raise ValueError("Invalid TCP peer")
        result.append((match[1] or match[2], int(match[3])))
    return result


class KoutenClient:
    """Synchronous native TCP client. Operations on one client are serialized.

    Construction stays lazy for compatibility; every new connection negotiates
    wire version and codec metadata before sending any application request.
    """

    def __init__(self, peers: str | Iterable[str], timeout: float = 10.0, *,
                 username: str = "", password: str = "", auth_token: str = "",
                 secret_key: str = "", galaxy: str = "", tls: bool = False,
                 tls_ca_file: str = "", tls_server_name: str = "",
                 tls_insecure_skip_verify: bool = False,
                 read_timeout: float | None = None, write_timeout: float | None = None,
                 max_frame_bytes: int = MAX_FRAME, max_redirects: int = 8,
                 retry_reads: bool = True):
        self.peers = _parse_peers(peers)
        self.timeout = timeout
        self.read_timeout = timeout if read_timeout is None else read_timeout
        self.write_timeout = timeout if write_timeout is None else write_timeout
        for value in (self.timeout, self.read_timeout, self.write_timeout):
            if isinstance(value, bool) or not math.isfinite(value) or not 0 < value <= 3600:
                raise ValueError("Timeout must be in (0, 3600] seconds")
        if type(max_frame_bytes) is not int or not 1 <= max_frame_bytes <= MAX_FRAME:
            raise ValueError("Invalid frame limit")
        if type(max_redirects) is not int or not 0 <= max_redirects <= 32:
            raise ValueError("Invalid redirect limit")
        self.max_frame_bytes, self.max_redirects = max_frame_bytes, max_redirects
        for value in (retry_reads, tls, tls_insecure_skip_verify):
            if type(value) is not bool:
                raise ValueError("Boolean options must be bool values")
        self.retry_reads = retry_reads
        if auth_token and not username:
            username, password = "token", auth_token
        for value in (username, password, galaxy):
            if not isinstance(value, str) or len(value.encode()) > 1024 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
                raise ValueError("Invalid authentication or galaxy field")
        if not username and (password or secret_key):
            raise ValueError("Authentication requires username")
        self.username, self.password, self.secret_key = username, password, secret_key
        self.galaxy = galaxy
        self.tls = tls or bool(tls_ca_file) or bool(tls_server_name) or tls_insecure_skip_verify
        self.tls_ca_file, self.tls_server_name = tls_ca_file, tls_server_name
        self.tls_insecure_skip_verify = tls_insecure_skip_verify
        self._connections: dict[int, Connection] = {}
        self._closed = False
        self._lock = RLock()

    @classmethod
    def connect(cls, peers: str | Iterable[str], timeout: float = 10.0, *,
                username: str = "", password: str = "", auth_token: str = "",
                secret_key: str = "", galaxy: str = "", tls: bool = False,
                tls_ca_file: str = "", tls_server_name: str = "",
                tls_insecure_skip_verify: bool = False,
                read_timeout: float | None = None, write_timeout: float | None = None,
                max_frame_bytes: int = MAX_FRAME, max_redirects: int = 8,
                retry_reads: bool = True) -> "KoutenClient":
        return cls(peers, timeout, username=username, password=password,
                   auth_token=auth_token, secret_key=secret_key, galaxy=galaxy,
                   tls=tls, tls_ca_file=tls_ca_file, tls_server_name=tls_server_name,
                   tls_insecure_skip_verify=tls_insecure_skip_verify,
                   read_timeout=read_timeout, write_timeout=write_timeout,
                   max_frame_bytes=max_frame_bytes, max_redirects=max_redirects,
                   retry_reads=retry_reads)

    def __repr__(self):
        return f"KoutenClient(closed={self._closed})"

    def _drop(self):
        for connection in self._connections.values():
            connection.close()
        self._connections.clear()

    def close(self):
        with self._lock:
            self._closed = True
            self._drop()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _connection(self, node: int) -> Connection:
        if self._closed:
            raise ConnectionException("TCP client is closed")
        if type(node) is not int or not 0 <= node < len(self.peers):
            raise ProtocolException("Node out of range")
        if node not in self._connections:
            self._connections[node] = Connection(self.peers[node], self)
        return self._connections[node]

    def _read_operation(self, operation):
        with self._lock:
            for attempt in range(2):
                try:
                    return operation()
                except KoutenError as error:
                    self._drop()
                    if self._closed or not self.retry_reads or attempt or not isinstance(error, ConnectionException):
                        raise

    def wire_version(self, node: int = 0) -> int:
        def operation():
            parts = self._connection(node).exchange("WIREVER")
            expect(parts, "WIREVER", 2)
            return number(parts[1], 1)
        return self._read_operation(operation)

    def health(self, node: int = 0) -> str:
        def operation():
            parts = self._connection(node).exchange("HEALTH")
            if parts[0] == "ERR":
                raise ServerException("Health request rejected")
            if len(parts) < 2 or parts[0] != "OK" or not re.fullmatch(r"node=[0-9]+", parts[1]):
                raise ProtocolException("Invalid health response")
            return " ".join(parts[1:])
        return self._read_operation(operation)

    def put(self, ring: str, payload: bytes | bytearray | memoryview | str,
            vector: Optional[Iterable[float]] = None, codec: PayloadCodec = "raw",
            node: int = 0) -> KoutenId:
        _codec(codec)
        ring_b = ring.encode("utf-8")
        payload_b = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        values = [] if vector is None else [float(v) for v in vector]
        if not all(math.isfinite(v) for v in values):
            raise ValueError("Vector must contain finite numbers")
        if not ring_b or len(ring_b) + len(payload_b) + len(values) * 4 > self.max_frame_bytes:
            raise ValueError("Invalid ring or request exceeds limit")
        body = ring_b + payload_b + struct.pack("<" + "f" * len(values), *values)
        with self._lock:
            attempted = [False]
            try:
                connection = self._connection(node)
                connection.send(f"PUTR {len(ring_b)} {len(payload_b)} {len(values)} {codec}", body, attempted)
                reply = connection.header()
                expect(reply, "ID", 7)
                try:
                    return KoutenId.parse(":".join(reply[1:]))
                except ValueError:
                    raise ProtocolException("Invalid returned ID") from None
            except KoutenError as error:
                self._drop()
                if attempted[0] and isinstance(error, (ConnectionException, ProtocolException)):
                    raise IndeterminateWriteException("Write outcome unknown; do not automatically retry") from None
                raise

    def put_codec(self, ring: str, payload: bytes | bytearray | memoryview | str,
                  codec: PayloadCodec, vector: Optional[Iterable[float]] = None,
                  node: int = 0) -> KoutenId:
        return self.put(ring, payload, vector, codec, node)

    def put_json(self, ring: str, value: Any, vector: Optional[Iterable[float]] = None,
                 node: int = 0) -> KoutenId:
        return self.put(ring, json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False), vector, "json", node)

    def put_nif(self, ring: str, payload: bytes | bytearray | memoryview | str,
                vector: Optional[Iterable[float]] = None, node: int = 0) -> KoutenId:
        return self.put(ring, payload, vector, "nif", node)

    def put_bif(self, ring: str, payload: bytes | bytearray | memoryview,
                vector: Optional[Iterable[float]] = None, node: int = 0) -> KoutenId:
        return self.put(ring, payload, vector, "bif", node)

    def _read(self, doc_id: KoutenId, selection: str | None, node: int | None):
        body = b"" if selection is None else selection.encode("utf-8")
        if len(body) > self.max_frame_bytes:
            raise ValueError("Selection exceeds limit")
        def operation():
            current, target = doc_id, 0 if node is None else node
            for redirects in range(self.max_redirects + 1):
                connection = self._connection(target)
                fields = str(current).replace(":", " ")
                connection.send(f"GETID {fields}" if selection is None else f"QRYID {fields} {len(body)}", body)
                reply = connection.header()
                if reply[0] in ("MISS", "GONE"):
                    expect(reply, reply[0], 1)
                    return None
                if reply[0] == "FWD":
                    if len(reply) not in (7, 8) or redirects == self.max_redirects:
                        raise ProtocolException("Invalid or excessive redirect")
                    try:
                        current = KoutenId.parse(":".join(reply[1:7]))
                    except ValueError:
                        raise ProtocolException("Invalid redirect ID") from None
                    if len(reply) == 8:
                        target = number(reply[7], len(self.peers) - 1)
                    continue
                expect(reply, "VAL", 4)
                number(reply[1], len(self.peers) - 1)
                size = number(reply[2], self.max_frame_bytes)
                try:
                    codec = _codec(reply[3])
                except ValueError:
                    raise ProtocolException("Unknown response codec") from None
                return EncodedPayload(connection.read(size), codec)
            raise ProtocolException("Excessive redirect")
        return self._read_operation(operation)

    def get_encoded(self, doc_id: KoutenId, node: Optional[int] = None) -> Optional[EncodedPayload]:
        return self._read(doc_id, None, node)

    def get(self, doc_id: KoutenId, node: Optional[int] = None) -> Optional[bytes]:
        result = self.get_encoded(doc_id, node)
        return None if result is None else result.payload

    def get_text(self, doc_id: KoutenId, node: Optional[int] = None) -> Optional[str]:
        result = self.get(doc_id, node)
        return None if result is None else result.decode("utf-8")

    def get_json(self, doc_id: KoutenId, node: Optional[int] = None) -> Any:
        result = self.get_text(doc_id, node)
        return None if result is None else json.loads(result)

    def query_encoded(self, doc_id: KoutenId, selection: str, node: Optional[int] = None) -> Optional[EncodedPayload]:
        return self._read(doc_id, selection, node)

    def query(self, doc_id: KoutenId, selection: str, node: Optional[int] = None) -> Optional[bytes]:
        result = self.query_encoded(doc_id, selection, node)
        return None if result is None else result.payload

    def query_text(self, doc_id: KoutenId, selection: str, node: Optional[int] = None) -> Optional[str]:
        result = self.query(doc_id, selection, node)
        return None if result is None else result.decode("utf-8")

    def query_json(self, doc_id: KoutenId, selection: str, node: Optional[int] = None) -> Any:
        result = self.query_text(doc_id, selection, node)
        return None if result is None else json.loads(result)

    def batch_get(self, ids: Iterable[KoutenId], node=None) -> list[Optional[bytes]]:
        # BGET v1 omits epochs and conflates empty payloads with misses. GETID
        # preserves identity, empty values, and server-directed ownership.
        return [self.get(doc_id, node) for doc_id in ids]
