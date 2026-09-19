"""Bounded synchronous framing; independent of database placement logic."""
from __future__ import annotations

import socket
import ssl
import time

from .errors import (ConnectionException, ConnectionTimeoutException,
                     ProtocolException, AuthenticationException, ServerException,
                     VersionMismatchException)
from .secure import (SecureState, encrypt_transport_frame,
                     decrypt_transport_frame, secret_response_hex)

HEADER_LIMIT = 8192
MAX_FRAME = 64 * 1024 * 1024


def number(text: str, maximum: int) -> int:
    if not text or len(text) > 20 or not text.isascii() or not text.isdecimal():
        raise ProtocolException("Invalid unsigned wire integer")
    value = int(text)
    if value > maximum:
        raise ProtocolException("Wire integer exceeds limit")
    return value


def expect(parts: list[str], tag: str, count: int, auth: bool = False) -> None:
    if parts[0] == "ERR":
        if auth:
            raise AuthenticationException("Authentication or galaxy rejected")
        raise ServerException("Server rejected request")
    if len(parts) != count or parts[0] != tag:
        raise ProtocolException("Invalid wire response")


class Connection:
    def __init__(self, peer: tuple[str, int], config):
        self.config = config
        self.secure: SecureState | None = None
        self.deadline = 0.0
        self.socket: socket.socket | None = None
        try:
            sock = socket.create_connection(peer, timeout=config.timeout)
            self.socket = sock
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if config.tls:
                context = ssl.create_default_context(cafile=config.tls_ca_file or None)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                if config.tls_insecure_skip_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                self.socket = context.wrap_socket(
                    sock, server_hostname=config.tls_server_name or peer[0])
            self._handshake()
        except TimeoutError:
            self.close()
            raise ConnectionTimeoutException("TCP connection timed out") from None
        except (OSError, ValueError):
            self.close()
            raise ConnectionException("Unable to connect or configure TLS") from None
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        self.secure = None

    def send(self, header: str, body: bytes = b"", attempt: list[bool] | None = None):
        if len(header) > HEADER_LIMIT or any(c in header for c in "\r\n\0"):
            raise ValueError("Invalid request header")
        if len(body) > self.config.max_frame_bytes:
            raise ValueError("Request exceeds frame limit")
        if self.socket is None:
            raise ConnectionException("TCP connection closed")
        frame = header.encode("utf-8") + b"\n" + body
        if self.secure:
            frame = encrypt_transport_frame(frame, self.secure.secret_key,
                                            self.secure.challenge_hex)
            frame = f"SEC {len(frame)}\n".encode("ascii") + frame
        try:
            self.socket.settimeout(self.config.write_timeout)
            if attempt is not None:
                attempt[0] = True
            self.socket.sendall(frame)
        except TimeoutError:
            raise ConnectionTimeoutException("TCP write timed out") from None
        except OSError:
            raise ConnectionException("TCP write failed") from None
        self.deadline = time.monotonic() + self.config.read_timeout

    def _raw(self, n: int) -> bytes:
        result = bytearray()
        while len(result) < n:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise ConnectionTimeoutException("TCP read timed out")
            if self.socket is None:
                raise ConnectionException("TCP connection closed")
            try:
                self.socket.settimeout(remaining)
                chunk = self.socket.recv(min(n - len(result), 65536))
            except TimeoutError:
                raise ConnectionTimeoutException("TCP read timed out") from None
            except OSError:
                raise ConnectionException("TCP read failed") from None
            if not chunk:
                raise ConnectionException("TCP connection closed")
            result.extend(chunk)
        return bytes(result)

    @staticmethod
    def _parse_line(line: bytes) -> list[str]:
        line = line.removesuffix(b"\r")
        if not line or any(b < 32 or b > 126 for b in line):
            raise ProtocolException("Invalid response header")
        return line.decode("ascii").split(" ")

    def _line(self, reader) -> list[str]:
        line = bytearray()
        while True:
            byte = reader(1)
            if byte == b"\n":
                return self._parse_line(bytes(line))
            if len(line) >= HEADER_LIMIT:
                raise ProtocolException("Response header exceeds limit")
            line.extend(byte)

    def _fill(self):
        parts = self._line(self._raw)
        expect(parts, "SEC", 2)
        n = number(parts[1], self.config.max_frame_bytes + HEADER_LIMIT + 41)
        if n < 40:
            raise ProtocolException("Invalid encrypted frame length")
        ciphertext = self._raw(n)
        state = self.secure
        assert state is not None
        try:
            plaintext = decrypt_transport_frame(ciphertext, state.secret_key,
                                                state.challenge_hex)
        except Exception:
            raise ProtocolException("Encrypted frame authentication failed") from None
        if len(state.buffer) + len(plaintext) > self.config.max_frame_bytes + HEADER_LIMIT + 1:
            raise ProtocolException("Encrypted response exceeds limit")
        state.buffer += plaintext

    def read(self, n: int) -> bytes:
        if self.secure is None:
            return self._raw(n)
        while len(self.secure.buffer) < n:
            self._fill()
        result = self.secure.buffer[:n]
        self.secure.buffer = self.secure.buffer[n:]
        return result

    def header(self) -> list[str]:
        return self._line(self.read)

    def exchange(self, header: str) -> list[str]:
        self.send(header)
        return self.header()

    def _handshake(self):
        c = self.config
        if c.username:
            if c.secret_key:
                chal = self.exchange("AUTHCHAL " + c.username)
                expect(chal, "CHAL", 2, auth=True)
                if len(chal[1]) != 64 or any(x not in "0123456789abcdefABCDEF" for x in chal[1]):
                    raise ProtocolException("Invalid authentication challenge")
                response = secret_response_hex(c.username, c.password, chal[1], c.secret_key)
                expect(self.exchange("AUTHRESP " + response), "OK", 2, auth=True)
                self.secure = SecureState(c.secret_key, chal[1])
            else:
                expect(self.exchange(f"AUTH {c.username} {c.password}"), "OK", 2, auth=True)
        if c.galaxy:
            expect(self.exchange("HELLO " + c.galaxy), "OK", 2, auth=True)
        version = self.exchange("WIREVER")
        expect(version, "WIREVER", 2, auth=True)
        if version[1] != "1":
            raise VersionMismatchException("Unsupported KoutenDB wire version")
        reply = self.exchange("CODECMETA ON")
        expect(reply, "OK", 2)
        if reply[1] != "codec-metadata":
            raise ProtocolException("Codec metadata negotiation failed")
