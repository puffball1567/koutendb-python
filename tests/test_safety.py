import unittest
from koutendb import KoutenClient, KoutenId, ConnectionException
from koutendb.transport import number
from koutendb.errors import ProtocolException


class SafetyTests(unittest.TestCase):
    def test_id_bounds(self):
        value = "18446744073709551615:4294967295:4294967295:1:60:0"
        self.assertEqual(KoutenId.parse(value).parent, 2**64 - 1)
        for value in ["-1:0:1:1:60:0", "1:0:1:nan:60:0", "1:0:1:1:0:0", "1:4294967296:1:1:60:0"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                KoutenId.parse(value)

    def test_invalid_configuration(self):
        for options in [{"timeout": 0}, {"read_timeout": float("nan")},
                        {"write_timeout": -1}, {"max_frame_bytes": 2**40},
                        {"max_redirects": 100}, {"username": "u\nHEALTH"}]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                KoutenClient("localhost:17301", **options)

    def test_closed_and_redacted(self):
        client = KoutenClient("localhost:17301", username="u", password="sensitive")
        self.assertNotIn("sensitive", repr(client))
        client.close()
        client.close()
        with self.assertRaises(ConnectionException):
            client.health()

    def test_wire_integer(self):
        self.assertEqual(number("0", 100), 0)
        for value in ["-1", "1e3", "101", "\uff11"]:
            with self.subTest(value=value), self.assertRaises(ProtocolException):
                number(value, 100)


if __name__ == "__main__":
    unittest.main()
