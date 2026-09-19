import os
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path

from koutendb import KoutenClient, KoutenId


DRIVER_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = Path(os.environ.get("KOUTENDB_CORE_DIR", DRIVER_ROOT.parent / "koutendb"))


class KoutenPythonDriverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.peers = os.environ.get(
            "KOUTEN_TEST_PEERS", "127.0.0.1:17831,127.0.0.1:17832"
        )
        cls.processes = []
        koutend = CORE_ROOT / "src" / "koutend"
        if not koutend.exists():
            raise RuntimeError(f"koutend not found: {koutend}")
        for i in range(2):
            cls.processes.append(
                subprocess.Popen(
                    [
                        str(koutend),
                        f"--id={i}",
                        f"--peers={cls.peers}",
                        "--slow-tick=1000",
                    ],
                    cwd=str(CORE_ROOT),
                )
            )

        cls.client = KoutenClient.connect(cls.peers, timeout=1.0)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                cls.client.health(0)
                cls.client.health(1)
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("koutend test cluster did not start")

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        for proc in cls.processes:
            proc.terminate()
        for proc in cls.processes:
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)

    def test_wire_version(self):
        self.assertGreaterEqual(self.client.wire_version(0), 1)

    def test_put_get_query_roundtrip(self):
        doc_id = self.client.put(
            "japan/tokyo",
            b'{"title":"Shinjuku","country":"JP"}',
            vector=[1.0, 0.0],
        )
        self.assertIsInstance(doc_id, KoutenId)
        self.assertEqual(
            self.client.get(doc_id), b'{"title":"Shinjuku","country":"JP"}'
        )
        self.assertEqual(self.client.query(doc_id, "{ title }"), b'{"title":"Shinjuku"}')

    def test_json_helpers(self):
        doc_id = self.client.put_json(
            "docs/python", {"title": "Python driver", "kind": "example"}
        )
        self.assertEqual(self.client.get_json(doc_id)["title"], "Python driver")
        self.assertEqual(self.client.query_json(doc_id, "{ kind }"), {"kind": "example"})
        encoded = self.client.get_encoded(doc_id)
        self.assertIsNotNone(encoded)
        assert encoded is not None
        self.assertEqual(encoded.codec, "json")
        self.assertEqual(json.loads(encoded.payload.decode("utf-8"))["title"], "Python driver")

        projected = self.client.query_encoded(doc_id, "{ title }")
        self.assertIsNotNone(projected)
        assert projected is not None
        self.assertEqual(projected.codec, "json")
        self.assertEqual(json.loads(projected.payload.decode("utf-8")), {"title": "Python driver"})

    def test_bif_codec_roundtrip(self):
        doc_id = self.client.put_bif("artifacts/bif", b"\x01\x02\x03\x04")
        encoded = self.client.get_encoded(doc_id)
        self.assertIsNotNone(encoded)
        assert encoded is not None
        self.assertEqual(encoded.codec, "bif")
        self.assertEqual(encoded.payload, b"\x01\x02\x03\x04")

    def test_batch_get_and_id_string_roundtrip(self):
        first = self.client.put("tenant/acme/orders", "order-1")
        second = self.client.put("tenant/acme/orders", "order-2")
        self.assertEqual(KoutenId.parse(str(first)), first)
        self.assertEqual(self.client.batch_get([first, second]), [b"order-1", b"order-2"])

    def test_batch_preserves_empty_payload_and_duplicates(self):
        empty = self.client.put("docs/empty", b"")
        self.assertEqual(self.client.batch_get([empty, empty]), [b"", b""])
        self.assertEqual(self.client.batch_get([]), [])


if __name__ == "__main__":
    unittest.main()
