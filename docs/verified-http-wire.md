# Complete native provider request encoding

Status: the [frozen validation record](../dev/validation/2026-10-18-http-wire.json)
binds implementation `37d32fd` to 2,489 portable tests without skips, all
264 required workflows in conformance and ordinary-release builds, 351 audited
Garrett obligations and 13 rejected encoder mutations. The 52 new obligations
include supporting lemmas; this is a scoped encoder result, not whole-service
secrecy or all-input Python/Rust equivalence.

Both native provider paths now use `http_wire::append_request` from the extracted
Rust core. The account and manifest adapters supply public method/target/host,
port, Accept and custom-header fields. The credential and canonical JSON body
remain borrowed. The encoder writes into the caller's existing zeroizing buffer
before any TCP/TLS connection; it introduces no secret-returning process command.
The version-1 broker protocol and optional identity/TPM selections are unchanged.

The shared encoder owns all request framing: the request line, Host and standard
headers, approved custom headers, the selected authentication line, optional JSON
Content-Type/Content-Length, the separator and exact body bytes. Its decimal
formatter is concrete extracted Rust, including the actual body length. All
validation completes before it modifies the output buffer.

The existing wire grammar remains narrow: GET/POST/PATCH; a bounded origin-form
target; an ASCII host and nonzero port; visible ASCII Accept/credential bytes;
bounded custom header names/values; case-insensitive reserved-name and duplicate
refusal; and a body of at most 2 MiB. The custom-header limit includes the existing
derived retry header. These are framing/resource bounds, not agent-action quotas.
Public header fields cannot select a second Host, authentication or transfer
framing field. Raw body bytes remain opaque to this primitive; the native caller
supplies canonical JSON. NUL in ordinary manifest arguments remains refused by
both Python and Rust before provider HTTP.

## Proof components

- `GarrettHttpWireDecimal.lean`: concrete decimal rendering, digit decoding and
  the exact append operation.
- `GarrettHttpWireHeaders.lean`: ASCII folding/comparison and the reviewed
  reserved field/prefix set.
- `GarrettHttpWireFormatting.lean`: exact custom-header bytes in caller order.
- `GarrettHttpWireValidation.lean`: accepted Host, Accept, method/target, header
  name/value grammar, case-insensitive uniqueness and body bound.
- `GarrettHttpWire.lean`: the request layout, admission/rejection and full-frame
  composition.

The append theorems state an explicit Vec capacity premise in the pinned model;
the production caller starts with an empty buffer and applies the stated input
bounds. These results concern byte construction and admission. Destination/route
selection, public-field conversion, canonical JSON serialization, TLS, provider
response parsing, OS isolation and whole-service I/O mediation remain separate
obligations. A correct encoder does not establish general secret noninterference
or protection against a compromised intended provider.

## Runtime evidence

`tests/test_rust_http_wire.py` runs native broker/client processes against a
recording HTTPS provider, then uses the independent Python executor for the same
operation. The provider retains every header instance instead of collapsing
duplicates into a dictionary. Cases cover both authentication methods, POST and
PATCH, eight policy headers, Unicode and CRLF-looking body text, exact serialized
body length, no extra authentication/transfer framing and NUL-argument refusal.

The core Rust tests check full request bytes, decimal formatting against the
standard formatter, binary body framing, reserved/colliding/injected headers,
credential injection and unchanged buffers on refusal. Existing account,
request-line, authentication, W6, OAuth and coordination workflows remain gates.
Compiler paths connect both provider writers to the shared encoder and header
admission, while keeping dominance, dependency/drop behavior and complete
mediation open.

```bash
python dev/verification/garrett.py record
python dev/verification/garrett.py mutate --mutation-filter '^http wire '
python dev/verification/system.py --proofs --full-tests --call-linkage
```

Use focused compilation of the changed Lean module during development. The
filtered mutation command is not a replay of the historical full campaign.
The 13 encoder mutations ran on `4b86a21`. The validated `37d32fd` adds only
CLI-test argv/documentation corrections; the Rust, proof and mutator inputs are
identical. The validation record retains the first failed portable attempt and
the deterministic leading-dash certificate-thumbprint regression.

Providers, keys and credentials in ordinary tests are synthetic; no VM, TPM or
live provider credential is needed.
