from __future__ import annotations

from dataclasses import dataclass
import json
import socket
import ssl
import struct
from typing import Any, Iterable, Literal, Optional

from .secure import (
    SecureState,
    decrypt_transport_frame,
    encrypt_transport_frame,
    secret_response_hex,
)


class KoutenError(Exception):
    """Raised when KoutenDB returns an error frame or the TCP connection fails."""


PayloadCodec = Literal["raw", "json", "nif", "bif"]
_PAYLOAD_CODECS = {"raw", "json", "nif", "bif"}


@dataclass(frozen=True)
class KoutenId:
    parent: int
    epoch: int
    seq: int
    t_write: float
    period: float
    head: float

    @classmethod
    def parse(cls, text: str) -> "KoutenId":
        parts = text.split(":")
        if len(parts) != 6:
            raise ValueError("KoutenId text must have 6 ':'-separated fields")
        return cls(
            parent=int(parts[0]),
            epoch=int(parts[1]),
            seq=int(parts[2]),
            t_write=float(parts[3]),
            period=float(parts[4]),
            head=float(parts[5]),
        )

    def __str__(self) -> str:
        return (
            f"{self.parent}:{self.epoch}:{self.seq}:"
            f"{self.t_write}:{self.period}:{self.head}"
        )


@dataclass(frozen=True)
class EncodedPayload:
    payload: bytes
    codec: PayloadCodec


def _parse_peers(peers: str | Iterable[str]) -> list[tuple[str, int]]:
    values = peers.split(",") if isinstance(peers, str) else list(peers)
    parsed: list[tuple[str, int]] = []
    for value in values:
        host, sep, port = value.rpartition(":")
        if not sep or not host or not port:
            raise ValueError(f"invalid peer '{value}', expected host:port")
        parsed.append((host, int(port)))
    if not parsed:
        raise ValueError("peers must not be empty")
    return parsed


def _vec_bytes(vector: Optional[Iterable[float]]) -> bytes:
    if vector is None:
        return b""
    values = [float(v) for v in vector]
    if not values:
        return b""
    return struct.pack("<" + "f" * len(values), *values)


def _as_bytes(payload: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return bytes(payload)


def _codec(codec: str) -> PayloadCodec:
    if codec not in _PAYLOAD_CODECS:
        raise ValueError(f"unsupported payload codec: {codec}")
    return codec  # type: ignore[return-value]


class KoutenClient:
    def __init__(
        self,
        peers: str | Iterable[str],
        timeout: float = 10.0,
        *,
        username: str = "",
        password: str = "",
        auth_token: str = "",
        secret_key: str = "",
        galaxy: str = "",
        tls: bool = False,
        tls_ca_file: str = "",
        tls_server_name: str = "",
        tls_insecure_skip_verify: bool = False,
    ):
        self.peers = _parse_peers(peers)
        self.timeout = timeout
        # A bare token becomes password auth under a reserved "token" user, the
        # same normalization the core client applies.
        if auth_token and not username:
            username, password = "token", auth_token
        self.username = username
        self.password = password
        self.secret_key = secret_key
        self.galaxy = galaxy
        self.tls = tls or bool(tls_ca_file) or bool(tls_server_name) or tls_insecure_skip_verify
        self.tls_ca_file = tls_ca_file
        self.tls_server_name = tls_server_name
        self.tls_insecure_skip_verify = tls_insecure_skip_verify
        self._socks: dict[int, socket.socket] = {}
        self._secure: dict[int, SecureState] = {}

    @classmethod
    def connect(
        cls,
        peers: str | Iterable[str],
        timeout: float = 10.0,
        *,
        username: str = "",
        password: str = "",
        auth_token: str = "",
        secret_key: str = "",
        galaxy: str = "",
        tls: bool = False,
        tls_ca_file: str = "",
        tls_server_name: str = "",
        tls_insecure_skip_verify: bool = False,
    ) -> "KoutenClient":
        return cls(
            peers,
            timeout=timeout,
            username=username,
            password=password,
            auth_token=auth_token,
            secret_key=secret_key,
            galaxy=galaxy,
            tls=tls,
            tls_ca_file=tls_ca_file,
            tls_server_name=tls_server_name,
            tls_insecure_skip_verify=tls_insecure_skip_verify,
        )

    def close(self) -> None:
        for sock in self._socks.values():
            try:
                sock.close()
            except OSError:
                pass
        self._socks.clear()
        self._secure.clear()

    def __enter__(self) -> "KoutenClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def wire_version(self, node: int = 0) -> int:
        parts = self._rpc(node, "WIREVER")
        if len(parts) != 2 or parts[0] != "WIREVER":
            raise KoutenError("WIREVER failed: " + " ".join(parts))
        return int(parts[1])

    def health(self, node: int = 0) -> str:
        parts = self._rpc(node, "HEALTH")
        if not parts or parts[0] != "OK":
            raise KoutenError("HEALTH failed: " + " ".join(parts))
        return " ".join(parts[1:])

    def put(
        self,
        ring: str,
        payload: bytes | bytearray | memoryview | str,
        vector: Optional[Iterable[float]] = None,
        codec: PayloadCodec = "raw",
        node: int = 0,
    ) -> KoutenId:
        ring_b = ring.encode("utf-8")
        payload_b = _as_bytes(payload)
        vec_b = _vec_bytes(vector)
        vec_dim = len(vec_b) // 4
        header = f"PUTR {len(ring_b)} {len(payload_b)} {vec_dim} {_codec(codec)}"
        parts = self._rpc(node, header, ring_b + payload_b + vec_b)
        if not parts or parts[0] != "ID" or len(parts) != 7:
            raise KoutenError("PUTR failed: " + " ".join(parts))
        return KoutenId(
            parent=int(parts[1]),
            epoch=int(parts[2]),
            seq=int(parts[3]),
            t_write=float(parts[4]),
            period=float(parts[5]),
            head=float(parts[6]),
        )

    def put_codec(
        self,
        ring: str,
        payload: bytes | bytearray | memoryview | str,
        codec: PayloadCodec,
        vector: Optional[Iterable[float]] = None,
        node: int = 0,
    ) -> KoutenId:
        return self.put(ring, payload, vector=vector, codec=codec, node=node)

    def put_json(
        self,
        ring: str,
        value: Any,
        vector: Optional[Iterable[float]] = None,
        node: int = 0,
    ) -> KoutenId:
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        return self.put(ring, payload, vector=vector, codec="json", node=node)

    def put_nif(
        self,
        ring: str,
        payload: bytes | bytearray | memoryview | str,
        vector: Optional[Iterable[float]] = None,
        node: int = 0,
    ) -> KoutenId:
        return self.put(ring, payload, vector=vector, codec="nif", node=node)

    def put_bif(
        self,
        ring: str,
        payload: bytes | bytearray | memoryview,
        vector: Optional[Iterable[float]] = None,
        node: int = 0,
    ) -> KoutenId:
        return self.put(ring, payload, vector=vector, codec="bif", node=node)

    def get(self, doc_id: KoutenId, node: Optional[int] = None) -> Optional[bytes]:
        return self._read_with_fallback("GETID", doc_id, b"", node=node)

    def get_encoded(
        self, doc_id: KoutenId, node: Optional[int] = None
    ) -> Optional[EncodedPayload]:
        return self._read_encoded_with_fallback("GETID", doc_id, b"", node=node)

    def get_text(self, doc_id: KoutenId, node: Optional[int] = None) -> Optional[str]:
        value = self.get(doc_id, node=node)
        return None if value is None else value.decode("utf-8")

    def get_json(self, doc_id: KoutenId, node: Optional[int] = None) -> Any:
        value = self.get_text(doc_id, node=node)
        return None if value is None else json.loads(value)

    def query(
        self, doc_id: KoutenId, selection: str, node: Optional[int] = None
    ) -> Optional[bytes]:
        selection_b = selection.encode("utf-8")
        return self._read_with_fallback("QRYID", doc_id, selection_b, node=node)

    def query_encoded(
        self, doc_id: KoutenId, selection: str, node: Optional[int] = None
    ) -> Optional[EncodedPayload]:
        selection_b = selection.encode("utf-8")
        return self._read_encoded_with_fallback("QRYID", doc_id, selection_b, node=node)

    def query_text(
        self, doc_id: KoutenId, selection: str, node: Optional[int] = None
    ) -> Optional[str]:
        value = self.query(doc_id, selection, node=node)
        return None if value is None else value.decode("utf-8")

    def query_json(self, doc_id: KoutenId, selection: str, node: Optional[int] = None) -> Any:
        value = self.query_text(doc_id, selection, node=node)
        return None if value is None else json.loads(value)

    def batch_get(self, ids: Iterable[KoutenId], node: int = 0) -> list[Optional[bytes]]:
        id_list = list(ids)
        body = "".join(
            f"{doc_id.parent} {doc_id.seq} {doc_id.period} {doc_id.head} {doc_id.t_write}\n"
            for doc_id in id_list
        ).encode("utf-8")
        parts = self._rpc(node, f"BGET {len(id_list)} {len(body)}", body)
        if len(parts) != 3 or parts[0] != "BVAL":
            raise KoutenError("BGET failed: " + " ".join(parts))
        expected = int(parts[1])
        payload = self._read_exact(node, int(parts[2]))
        out: list[Optional[bytes]] = []
        pos = 0
        for _ in range(expected):
            nl = payload.find(b"\n", pos)
            if nl < 0:
                raise KoutenError("BGET payload length header missing")
            length = int(payload[pos:nl].decode("utf-8"))
            pos = nl + 1
            if length == 0:
                out.append(None)
            else:
                out.append(payload[pos : pos + length])
            pos += length
        return out

    def _read_id_encoded(
        self, op: str, doc_id: KoutenId, selection: bytes, node: int
    ) -> Optional[EncodedPayload]:
        header = (
            f"{op} {doc_id.parent} {doc_id.epoch} {doc_id.seq} "
            f"{doc_id.t_write} {doc_id.period} {doc_id.head}"
        )
        if op == "QRYID":
            header += f" {len(selection)}"
        parts = self._rpc(node, header, selection)
        if not parts:
            raise KoutenError(f"{op} returned an empty response")
        if parts[0] == "MISS":
            return None
        if parts[0] == "ERR":
            raise KoutenError(" ".join(parts[1:]))
        if parts[0] == "FWD":
            if len(parts) != 7:
                raise KoutenError("invalid FWD response: " + " ".join(parts))
            fwd = KoutenId(
                parent=int(parts[1]),
                epoch=int(parts[2]),
                seq=int(parts[3]),
                t_write=float(parts[4]),
                period=float(parts[5]),
                head=float(parts[6]),
            )
            return self._read_id_encoded(op, fwd, selection, node=node)
        if parts[0] != "VAL" or len(parts) not in (3, 4):
            raise KoutenError(f"{op} failed: " + " ".join(parts))
        codec = _codec(parts[3]) if len(parts) == 4 else ("json" if op == "QRYID" else "raw")
        return EncodedPayload(self._read_exact(node, int(parts[2])), codec)

    def _read_id(self, op: str, doc_id: KoutenId, selection: bytes, node: int) -> Optional[bytes]:
        value = self._read_id_encoded(op, doc_id, selection, node=node)
        return None if value is None else value.payload

    def _read_with_fallback(
        self, op: str, doc_id: KoutenId, selection: bytes, node: Optional[int]
    ) -> Optional[bytes]:
        if node is not None:
            return self._read_id(op, doc_id, selection, node=node)
        first = self._read_id(op, doc_id, selection, node=0)
        if first is not None or len(self.peers) == 1:
            return first
        for peer_node in range(1, len(self.peers)):
            value = self._read_id(op, doc_id, selection, node=peer_node)
            if value is not None:
                return value
        return None

    def _read_encoded_with_fallback(
        self, op: str, doc_id: KoutenId, selection: bytes, node: Optional[int]
    ) -> Optional[EncodedPayload]:
        if node is not None:
            return self._read_id_encoded(op, doc_id, selection, node=node)
        first = self._read_id_encoded(op, doc_id, selection, node=0)
        if first is not None or len(self.peers) == 1:
            return first
        for peer_node in range(1, len(self.peers)):
            value = self._read_id_encoded(op, doc_id, selection, node=peer_node)
            if value is not None:
                return value
        return None

    def _rpc(self, node: int, header: str, payload: bytes = b"") -> list[str]:
        last_error: Optional[BaseException] = None
        for attempt in range(2):
            try:
                self._socket_for(node)
                self._send_frame(node, header, payload)
                return self._read_header(node)
            except OSError as err:
                last_error = err
                self._drop_socket(node)
                if attempt == 1:
                    raise KoutenError(str(err)) from err
        raise KoutenError(str(last_error))

    def _socket_for(self, node: int) -> socket.socket:
        if node < 0 or node >= len(self.peers):
            raise IndexError(f"node out of range: {node}")
        sock = self._socks.get(node)
        if sock is not None:
            return sock
        host, port = self.peers[node]
        sock = socket.create_connection((host, port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if self.tls:
            sock = self._wrap_tls(sock, host)
        self._socks[node] = sock
        try:
            self._handshake(node)
        except BaseException:
            self._drop_socket(node)
            raise
        return sock

    def _wrap_tls(self, sock: socket.socket, host: str) -> ssl.SSLSocket:
        # Verification stays on unless the caller explicitly opts out. A CA file
        # anchors trust to a private CA / self-signed certificate while keeping
        # certificate and hostname checks; the insecure switch is the only path
        # that disables them, and it is for local smoke tests only.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.tls_insecure_skip_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            if self.tls_ca_file:
                context.load_verify_locations(self.tls_ca_file)
            else:
                context.load_default_certs()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        server_hostname = self.tls_server_name or host
        try:
            return context.wrap_socket(sock, server_hostname=server_hostname)
        except ssl.SSLError as err:
            sock.close()
            raise KoutenError(f"TLS handshake failed: {err}") from err

    def _handshake(self, node: int) -> None:
        if self.username:
            if self.secret_key:
                self._send_frame(node, "AUTHCHAL " + self.username)
                chal = self._read_header(node)
                if len(chal) < 2 or chal[0] != "CHAL":
                    raise KoutenError("AUTHCHAL failed: " + " ".join(chal))
                response = secret_response_hex(
                    self.username, self.password, chal[1], self.secret_key
                )
                self._send_frame(node, "AUTHRESP " + response)
                reply = self._read_header(node)
                if not reply or reply[0] != "OK":
                    raise KoutenError("AUTHRESP failed: " + " ".join(reply))
                # Every frame after this point is sealed with the transport key.
                self._secure[node] = SecureState(self.secret_key, chal[1])
            else:
                self._send_frame(node, f"AUTH {self.username} {self.password}")
                reply = self._read_header(node)
                if not reply or reply[0] != "OK":
                    raise KoutenError("AUTH failed: " + " ".join(reply))
        if self.galaxy:
            self._send_frame(node, "HELLO " + self.galaxy)
            reply = self._read_header(node)
            if not reply or reply[0] != "OK":
                raise KoutenError("HELLO failed: " + " ".join(reply))
        self._send_frame(node, "CODECMETA ON")
        reply = self._read_header(node)
        if not reply or reply[0] != "OK":
            raise KoutenError("CODECMETA failed: " + " ".join(reply))

    def _drop_socket(self, node: int) -> None:
        self._secure.pop(node, None)
        sock = self._socks.pop(node, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _send_frame(self, node: int, header: str, payload: bytes = b"") -> None:
        plaintext = header.encode("utf-8") + b"\n" + payload
        state = self._secure.get(node)
        if state is None:
            self._socks[node].sendall(plaintext)
        else:
            ciphertext = encrypt_transport_frame(
                plaintext, state.secret_key, state.challenge_hex
            )
            self._socks[node].sendall(
                b"SEC " + str(len(ciphertext)).encode("ascii") + b"\n" + ciphertext
            )

    def _read_secure_frame(self, node: int) -> None:
        sock = self._socks[node]
        header = self._raw_read_line(sock).split(" ")
        if len(header) < 2 or header[0] != "SEC":
            raise KoutenError("expected secure frame, got: " + " ".join(header))
        ciphertext = self._raw_read_exact(sock, int(header[1]))
        state = self._secure[node]
        state.buffer += decrypt_transport_frame(
            ciphertext, state.secret_key, state.challenge_hex
        )

    def _read_header(self, node: int) -> list[str]:
        state = self._secure.get(node)
        if state is None:
            return self._raw_read_line(self._socks[node]).split(" ")
        while True:
            nl = state.buffer.find(b"\n")
            if nl >= 0:
                line = state.buffer[:nl]
                state.buffer = state.buffer[nl + 1 :]
                return line.decode("utf-8").split(" ")
            self._read_secure_frame(node)

    def _read_exact(self, node: int, n: int) -> bytes:
        state = self._secure.get(node)
        if state is None:
            return self._raw_read_exact(self._socks[node], n)
        while len(state.buffer) < n:
            self._read_secure_frame(node)
        out = state.buffer[:n]
        state.buffer = state.buffer[n:]
        return out

    def _raw_read_line(self, sock: socket.socket) -> str:
        chunks: list[bytes] = []
        while True:
            b = sock.recv(1)
            if not b:
                raise KoutenError("connection closed")
            if b == b"\n":
                return b"".join(chunks).decode("utf-8")
            chunks.append(b)

    def _raw_read_exact(self, sock: socket.socket, n: int) -> bytes:
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise KoutenError("connection closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
