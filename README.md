# RocheDB Python Driver

Pure Python TCP driver for [RocheDB](https://github.com/puffball1567/rochedb).

This driver talks to `roched` over RocheDB's high-level wire protocol. It does
not reimplement RocheDB's ring-key, period, head-angle, or placement rules.
Applications pass a human-readable ring name, and RocheDB returns a typed ID.

## Status

- package target: PyPI `rochedb` after validation
- current mode: native TCP wire driver
- Python: 3.10+
- runtime dependencies: none
- RocheDB core: running `roched` node or cluster

Implemented:

- persistent TCP connections
- `wire_version` / `health`
- `put` / `put_json`
- `get` / `get_text` / `get_json`
- `query` / `query_text` / `query_json`
- `batch_get`
- typed `RocheId`
- one reconnect retry
- context manager support

Planned:

- PyPI publication
- authentication / secret-key handshake support
- retrieve / atlas wire APIs once the public wire contract is finalized for drivers
- connection pooling

## Install For Local Development

Until PyPI publication, install from a checkout:

```sh
python3 -m pip install -e .
```

Build `roched` from the RocheDB core repository:

```sh
git clone https://github.com/puffball1567/rochedb.git
cd rochedb
nimble install -y
nim c -d:release --nimcache:/tmp/nimcache_roched -o:src/roched src/roched.nim
```

## Example

```python
from rochedb import RocheClient

with RocheClient.connect("127.0.0.1:17301") as db:
    doc_id = db.put_json(
        "docs/japan/support",
        {"title": "Tokyo support note", "country": "JP"},
        vector=[1.0, 0.0],
    )

    print(db.get_json(doc_id))
    print(db.query_json(doc_id, "{ title }"))
```

## Test

From this driver repository, point `ROCHEDB_CORE_DIR` at a RocheDB checkout:

```sh
ROCHEDB_CORE_DIR=/path/to/rochedb python3 -m unittest discover -s tests
```

The test starts a two-node local `roched` cluster and verifies put/get/query,
JSON helpers, `wire_version`, and `batch_get`.

## Why A Native Wire Driver?

The Python driver is intended for API services, scripts, experiments, and
AI/RAG validation where a running RocheDB server or cluster is the natural
boundary. It keeps Python out of RocheDB's placement internals and uses the same
ring-oriented API that other external drivers should use.
