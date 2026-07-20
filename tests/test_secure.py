"""Unit tests for the shared-secret transport crypto (no server required).

These lock down the security-critical properties of secure.py: confidentiality,
authenticated integrity, and key separation. They require the `secure` extra
(PyNaCl); the whole module is skipped if it is not installed.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from koutendb import secure  # noqa: E402

try:
    import nacl.secret  # noqa: F401

    _HAVE_PYNACL = True
except ImportError:
    _HAVE_PYNACL = False


@unittest.skipUnless(_HAVE_PYNACL, "PyNaCl (the 'secure' extra) is required")
class TransportCryptoTest(unittest.TestCase):
    SECRET = "shared-secret"
    CHAL = "0a1b2c3d4e5f"

    def test_ciphertext_hides_plaintext(self):
        pt = b"PUTR docs 12 0 json"
        ct = secure.encrypt_transport_frame(pt, self.SECRET, self.CHAL)
        self.assertNotIn(pt, ct)
        # 24-byte nonce + 16-byte Poly1305 tag of overhead.
        self.assertEqual(len(ct), len(pt) + 24 + 16)

    def test_roundtrip(self):
        pt = b"hello kouten"
        ct = secure.encrypt_transport_frame(pt, self.SECRET, self.CHAL)
        self.assertEqual(secure.decrypt_transport_frame(ct, self.SECRET, self.CHAL), pt)

    def test_tampered_ciphertext_is_rejected(self):
        ct = bytearray(secure.encrypt_transport_frame(b"payload", self.SECRET, self.CHAL))
        ct[-1] ^= 0x01
        with self.assertRaises(Exception):
            secure.decrypt_transport_frame(bytes(ct), self.SECRET, self.CHAL)

    def test_wrong_key_cannot_decrypt(self):
        ct = secure.encrypt_transport_frame(b"payload", self.SECRET, self.CHAL)
        with self.assertRaises(Exception):
            secure.decrypt_transport_frame(ct, "other-secret", self.CHAL)

    def test_challenge_separates_transport_keys(self):
        ct = secure.encrypt_transport_frame(b"payload", self.SECRET, self.CHAL)
        with self.assertRaises(Exception):
            secure.decrypt_transport_frame(ct, self.SECRET, "ffffffffffff")

    def test_nonce_is_randomized_per_frame(self):
        pt = b"same message"
        a = secure.encrypt_transport_frame(pt, self.SECRET, self.CHAL)
        b = secure.encrypt_transport_frame(pt, self.SECRET, self.CHAL)
        self.assertNotEqual(a, b)

    def test_response_is_lowercase_hex(self):
        resp = secure.secret_response_hex("alice", "secret", self.CHAL, self.SECRET)
        int(resp, 16)  # must be valid hex
        self.assertEqual(resp, resp.lower())


if __name__ == "__main__":
    unittest.main()
