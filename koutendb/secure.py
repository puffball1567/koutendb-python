"""libsodium-backed shared-secret challenge response and secure transport.

This mirrors the KoutenDB core `kouten/auth` module byte-for-byte so the
Python wire driver interoperates with the Nim server:

- key derivation uses BLAKE2b (libsodium ``crypto_generichash``), available in
  the standard library as ``hashlib.blake2b``;
- the challenge response and transport frames use ``crypto_secretbox``
  (XSalsa20-Poly1305), which requires PyNaCl. PyNaCl is imported lazily so the
  driver stays usable for plaintext / password-only connections without it.
"""

from __future__ import annotations

import hashlib

_AUTH_DOMAIN = b"koutendb-auth-v1"
_KEY_BYTES = 32


def _require_secretbox():
    try:
        from nacl.secret import SecretBox
    except ImportError as exc:  # pragma: no cover - exercised via error path
        raise RuntimeError(
            "secret-key authentication requires PyNaCl. Install it with "
            "'pip install koutendb[secure]' or 'pip install pynacl'."
        ) from exc
    return SecretBox


def _blake2b32(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=_KEY_BYTES).digest()


def _box_key(secret_key: bytes) -> bytes:
    return _blake2b32(_AUTH_DOMAIN + b"\0box\0" + secret_key)


def _transport_key(secret_key: bytes, challenge_hex: bytes) -> bytes:
    return _blake2b32(
        _AUTH_DOMAIN + b"\0transport\0" + challenge_hex + b"\0" + secret_key
    )


def _auth_message(username: bytes, password: bytes, challenge_hex: bytes) -> bytes:
    return _AUTH_DOMAIN + b"\n" + username + b"\n" + password + b"\n" + challenge_hex


def secret_response_hex(
    username: str, password: str, challenge_hex: str, secret_key: str
) -> str:
    """Return the hex-encoded sealed response for an AUTHRESP frame."""
    box = _require_secretbox()(_box_key(secret_key.encode("utf-8")))
    message = _auth_message(
        username.encode("utf-8"), password.encode("utf-8"), challenge_hex.encode("utf-8")
    )
    return bytes(box.encrypt(message)).hex()


def encrypt_transport_frame(
    plaintext: bytes, secret_key: str, challenge_hex: str
) -> bytes:
    box = _require_secretbox()(
        _transport_key(secret_key.encode("utf-8"), challenge_hex.encode("utf-8"))
    )
    return bytes(box.encrypt(plaintext))


def decrypt_transport_frame(
    ciphertext: bytes, secret_key: str, challenge_hex: str
) -> bytes:
    box = _require_secretbox()(
        _transport_key(secret_key.encode("utf-8"), challenge_hex.encode("utf-8"))
    )
    return bytes(box.decrypt(ciphertext))


class SecureState:
    """Decrypted-plaintext buffer for one secured connection."""

    __slots__ = ("secret_key", "challenge_hex", "buffer")

    def __init__(self, secret_key: str, challenge_hex: str):
        self.secret_key = secret_key
        self.challenge_hex = challenge_hex
        self.buffer = b""
