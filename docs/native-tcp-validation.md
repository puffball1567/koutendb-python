# Native TCP Validation

Date: 2026-09-19

Local Linux verification against the shared KoutenDB conformance harness at
core commit `e36b424bcfd9cd0dfa24ae121f4b4dd028b0eaac`:

- All 27 scripted protocol/failure cases passed.
- All six real-server modes passed: plain, password, token, secret, TLS, TLS+secret.
- Verified Unicode, empty/binary data and 1 MiB payload round trips.
- Verified invalid credentials, certificate rejection, hostname mismatch,
  bounded redirects, partial frames, timeout, disconnection and unsafe-write replay prevention.

- Unit, two-node integration and crypto tests: 17 passed.
- Empty payloads and duplicate IDs retain their values and ordering in batch_get.
- Wheel and source distribution build: passed; transport/error modules included.

Linux/macOS workflow coverage is configured but has not yet been run on GitHub
for this branch. These results are not a release publication, load test or
long-duration operational certification.

See [native TCP usage and reproduction commands](native-tcp.md).
