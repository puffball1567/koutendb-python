# Native TCP Safety Update

Python already uses native TCP and still needs no libkoutendb or FFI. This
release hardens that transport rather than adding another one.

```python
from koutendb import KoutenClient, IndeterminateWriteException

with KoutenClient.connect(
    ["127.0.0.1:17301"], timeout=3,
    read_timeout=5, write_timeout=5,
) as db:
    document_id = db.put_json("articles", {"title": "Hello"})
    print(db.get_json(document_id))
```

For TLS set `tls=True`, `tls_ca_file="ca.pem"` and
`tls_server_name="db.example.com"`. Omit the CA file to use system roots.
Credentials are `username`, `password`, `auth_token`, `secret_key` and `galaxy`.
Shared-secret mode requires `pip install 'koutendb[secure]'`; ordinary TLS uses
Python's standard library.

New exceptions inherit KoutenError, so existing broad error handlers still work:
ConnectionException, ConnectionTimeoutException, AuthenticationException,
ProtocolException, VersionMismatchException, ServerException and
IndeterminateWriteException.

Construction remains lazy. The first operation negotiates the protocol before
use. A client serializes operations with a lock; close is now terminal.
For local development install this checkout with `pip install -e '.[secure]'`.
DNS resolution is OS-controlled and may outlast the connection timeout.

## Behavior Changes

Unsafe automatic write replay and all-peer miss probing have been removed.
Reads follow explicit server redirects only. Keep the peer ordering consistent
with the server cluster.

`batch_get` now uses ordered GETID requests. Wire-v1 BGET omits the epoch and
conflates an empty value with a miss. This prioritizes correct identity and
empty-value handling, but means one request per ID rather than one BGET frame.
Do not expect the previous batch throughput. The return shape and input ordering
are unchanged.

```sh
KOUTENDB_CORE_DIR=../koutendb python3 -m unittest discover -s tests
bash ../koutendb/scripts/native_driver_conformance.sh python3 "$PWD/tests/tcp_adapter.py"
```

## Server Setup

Run a TLS-enabled `koutend` build. For a local-only first test:

```sh
koutend --id=0 --peers=127.0.0.1:17301 --data=./kouten-data
```

Keep plaintext connections on localhost or an isolated, trusted private network.
A Docker network is not a substitute for access control. Use verified TLS when
traffic crosses a trust boundary. For password authentication, start the server
with `--user=app --password=...`; prefer the server's configuration/secret
management facilities for production rather than putting secrets in shell history.

Native TCP implements wire version 1: WIREVER, CODECMETA, PUTR, GETID, QRYID,
HEALTH, authentication and bounded FWD handling. It is not a replacement for
every embedded/admin API. It uses server-provided IDs and does not calculate
ring placement or orbit ownership. Peer ordering must match the server cluster
configuration, because explicit redirect owners are node indexes.

## Safety Contract

- Every new connection authenticates, checks WIREVER and enables codec metadata
  before sending application requests. Unsupported versions fail closed.
- Headers are bounded to 8 KiB; payload frames default to at most 64 MiB.
  The configurable payload cap cannot exceed that hard limit.
- Partial reads/writes are handled. A read deadline covers the complete response,
  not a fresh timeout for every fragment.
- A read may reconnect and retry once. An unknown write outcome is never retried.
- After a broken or malformed response the connection is discarded.
- Redirects default to eight hops (configurable up to 32), and an out-of-range
  owner is rejected. Missing values do not trigger a scan of every server.
- CA and hostname verification are enabled by default. TLS 1.2 is the minimum.
  Insecure verification bypass is explicitly development-only.
- Password/token and shared-secret challenge authentication are supported.
  Library transport errors do not include raw server error text or credentials.

A successful send is not proof that a write committed. If the connection breaks
or the reply is malformed after a PUT may have been sent, handle an
**indeterminate write** separately from a definite server rejection. Do not
blindly repeat the insert or assume a fallback database is now authoritative.
Reconcile at the application level until a server-side idempotency contract is
available.

The pre-v1 protocol is version-checked, not promised compatible with future
versions. Authentication errors, protocol errors, connection failures, timeouts,
server rejections and indeterminate writes are distinguishable.

## Verification

The adapter in this repository runs against KoutenDB's language-independent
`scripts/native_driver_conformance.py` suite, pinned in CI to core commit
`e36b424bcfd9cd0dfa24ae121f4b4dd028b0eaac`.

The shared matrix covers 27 scripted cases: fragmented/empty/Unicode/binary
responses, missing values, projections, invalid lengths/codecs/headers, redacted
server errors, version mismatches, connection loss, partial-response retry,
timeouts, backpressure, redirects and poisoned-connection disposal.
Six real-server configurations cover plaintext, password, token, shared-secret,
TLS and TLS plus shared-secret; these include 1 MiB round trips, invalid
credentials, untrusted certificates and hostname mismatch.

These are bounded correctness/integration checks, not endurance or throughput
benchmarks. Linux results are checked locally; Linux/macOS CI must pass before
release. Existing embedded regressions remain separate from native TCP checks.
