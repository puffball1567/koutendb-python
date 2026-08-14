# KoutenDB Python Driver

Pure Python TCP driver for [KoutenDB](https://github.com/puffball1567/koutendb).

This driver talks to `koutend` over KoutenDB's high-level wire protocol. It does
not reimplement KoutenDB's ring-key, period, head-angle, or placement rules.
Applications pass a human-readable ring name, and KoutenDB returns a typed ID.

## Status

- package: PyPI [`koutendb`](https://pypi.org/project/koutendb/) v0.2.1
- current mode: native TCP wire driver
- Python: 3.10+
- runtime dependencies: none
- KoutenDB core: running `koutend` node or cluster

Implemented:

- persistent TCP connections
- `wire_version` / `health`
- `put` / `put_codec` / `put_json` / `put_nif` / `put_bif`
- `get` / `get_encoded` / `get_text` / `get_json`
- `query` / `query_encoded` / `query_text` / `query_json`
- codec metadata negotiation with `CODECMETA ON`
- `batch_get`
- direct owner redirects from extended `FWD ... owner` responses
- routed multi-node `batch_get` fallback with stable input ordering
- typed `KoutenId`
- one reconnect retry
- context manager support
- username/password, shared-secret transport, and TLS authentication

Planned:

- retrieve / atlas wire APIs once the public wire contract is finalized for drivers
- ring-read filters/projection once the public wire contract is finalized for drivers
- connection pooling

## Install

Install the published package from PyPI:

```sh
python3 -m pip install koutendb
```

For local driver development, install from a checkout:

```sh
python3 -m pip install -e .
```

Build `koutend` from the KoutenDB core repository:

```sh
git clone https://github.com/puffball1567/koutendb.git
cd koutendb
nimble install -y
nim c -d:release --nimcache:/tmp/nimcache_koutend -o:src/koutend src/koutend.nim
```

## Example

```python
from koutendb import KoutenClient

with KoutenClient.connect("127.0.0.1:17301") as db:
    doc_id = db.put_json(
        "docs/japan/support",
        {"title": "Tokyo support note", "country": "JP"},
        vector=[1.0, 0.0],
    )

    print(db.get_json(doc_id))
    print(db.get_encoded(doc_id).codec)
    print(db.query_json(doc_id, "{ title }"))
```

## Authentication and TLS

`connect` accepts credentials and TLS options. Password auth and TLS use only
the standard library. Shared-secret (`secret_key`) challenge-response and the
encrypted transport it enables additionally need libsodium via PyNaCl — install
the `secure` extra:

```sh
pip install koutendb[secure]
```

Connect over TLS with shared-secret auth, verifying the server against a CA or
self-signed certificate PEM (certificate verification stays on):

```python
from koutendb import KoutenClient

db = KoutenClient.connect(
    "127.0.0.1:17301",
    username="alice",
    password="secret",
    secret_key="shared-secret",
    tls_ca_file="/path/to/server.crt",
)
```

Password-only auth over TLS needs no extra dependency:

```python
db = KoutenClient.connect(
    "127.0.0.1:17301", username="alice", password="secret",
    tls_ca_file="/path/to/server.crt",
)
```

`tls_insecure_skip_verify=True` disables certificate verification. The
connection is then encrypted but unauthenticated and trivially impersonable, so
it is for local smoke tests only — never a production server. Prefer
`tls_ca_file` for self-signed certificates.

## Test

From this driver repository, point `KOUTENDB_CORE_DIR` at a KoutenDB checkout:

```sh
KOUTENDB_CORE_DIR=/path/to/koutendb python3 -m unittest discover -s tests
```

The test starts a two-node local `koutend` cluster and verifies put/get/query,
JSON helpers, codec metadata, BIF opaque payloads, `wire_version`, and
`batch_get`.

## Why A Native Wire Driver?

The Python driver is intended for API services, scripts, experiments, and
AI/RAG validation where a running KoutenDB server or cluster is the natural
boundary. It keeps Python out of KoutenDB's placement internals and uses the same
ring-oriented API that other external drivers should use.
