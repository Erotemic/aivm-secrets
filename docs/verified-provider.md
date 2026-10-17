# Rust-owned credential use and public-result release

The explicit `account-status-v1` development profile implements an entire
Rust client-to-provider path. It uses the existing nested Garrett surrogate
and version-1 request frame, with `profile.read` mapped to `GET /v1/account`
on one operator-pinned HTTPS origin. No Python broker runs in that path.
This is an incremental implementation of the broader
[acceptance plan](planning/aivm-secrets-garrett-verification.md), not a general
Rust replacement for every Python policy, provider operation or OAuth service.

## Credential and effect boundary

The Rust custody module loads a private credential file, validates 16–4096
visible ASCII bytes without whitespace, and seals it with the reference
`aivs1` envelope format. The inner key is random and process-local. Only the
certificate-bound outer surrogate leaves the service in its readiness frame.
A restart creates a new inner key and grant; an old surrogate fails even when
the outer key and certificate remain unchanged.

For each request the service obtains the certificate from actual TLS, reads
current enrollment, authenticates the outer envelope, checks binding, opens
the inner capability, and checks its exact binding, policy digest, grant ID,
issuance/expiry and monotonic lifetime. The extracted controller authorizes
the exact named operation before calling the private executor. There is no
request-count limit in this profile. `describe` releases profile metadata;
`renounce` deactivates the grant. Delegation and request arguments are refused.

The private executor receives the selected route and opaque credential.
It connects to the configured IP/port, verifies the configured DNS name
against the pinned provider CA, then inserts the credential into exactly
`Authorization: Bearer …` or `X-API-Key: …`. Method and path are fixed by the
profile. The client cannot supply a URL, header, query, method or alternate
destination. There are no proxy-environment hooks, redirects, retries, or TLS
key logging. TLS 1.3, connection/read/write deadlines, bounded response parsing
and a fixed wall-clock watchdog apply.

The HTTP adapter requires a successful JSON response with unambiguous bounded
Content-Length or strict chunked framing. It rejects duplicate headers,
conflicting framing, compression, unsupported chunk extensions/trailers,
truncation and oversized data. It never releases provider error bodies or
headers. Its framing decisions follow the security boundary described by
[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3); this adapter
is not a proof of the HTTP standard or a general-purpose HTTP client.

The audit file records fixed events plus the grant/policy identifiers.
Dispatch intent includes the authenticated public identity, inner binding,
operation and exact route. It is synced before provider I/O; completion is
synced before releasing the result. The sink holds an exclusive session lock,
rejects incomplete existing tails and stays failed after a write/sync failure.
Audit failures fail closed. No credential, inner token,
provider body, HTTP header or arbitrary exception text enters those records.
The custody/executor module exposes no credential formatting/serialization or
general callback that could obtain plaintext credentials. Trusted libraries
may still copy secret data in host memory; zeroization is not a proof that
every copy disappears.

## Explicit disclosure contract

A valid provider response has a nonnegative `i64` field `id` and Boolean field
`active`. The released result contains exactly those fields. All other JSON
content is discarded, including reflected credentials, refresh tokens,
diagnostics and nested data. Invalid response structure produces a closed
error code without reflecting bytes.

This stronger release contract is **selected explicitly** by the profile.
The general Python broker's existing raw-result/reflection semantics remain
unchanged. Parity tests compare the common inner envelope, provider request,
credential substitution and selected public fields. They do not claim that
the projected result equals the Python broker's complete raw result.

The [composed request controller](verified-composition.md) joins outer opening,
inner opening, authorization, audit acknowledgement, execution and release.
The underlying credential-use controller in
[`credential_use.rs`](../rust/crates/aivm-secrets-garrett-core/src/credential_use.rs)
and its proofs in [`Garrett.lean`](../proofs/Garrett.lean) cover:

- Exact current-grant and operation authorization, including denials.
- No executor call for an inactive grant or unauthorized operation.
- Successful use calls the executor with the selected route and the opened
  credential, under its explicit execution contract.
- Successful release is exactly the approved typed projection.
- Two-run release noninterference for arbitrary discarded response bytes.
- Credential-use noninterference when credentials/private response content
  change while the provider's declared public `id` and `active` agree.
- A successful authorized execution, rather than an always-deny controller.

The last condition matters: a malicious provider can encode a credential in
an integer, a Boolean sequence, an error, or timing. These theorems do not
prove that a provider's designated public fields are independent of secrets.
They establish the broker's projection given that disclosure contract.
Parser/HTTP/TLS/crypto/filesystem refinement, whole-service traces, timing and
metadata, host compromise, rollback, and physical TPM provenance remain
explicit assurance work. The existing symbolic secrecy model is separate.

## Select the profile

Use the common server fields documented in
[verified Garrett](verified-garrett.md). Replace `broker_socket` and
`public_key_hex` with the following explicit provider selection:

```json
{
  "signing_key_file": "/private/ed25519-seed.bin",
  "lifetime": 300,
  "binding": {
    "owner_uid": 1000,
    "access_identity": "principal-test",
    "vm": "vm-test",
    "channel": "0123456789abcdef0123456789abcdef"
  },
  "provider": {
    "profile": "account-status-v1",
    "host": "api.example.test",
    "address": "127.0.0.1",
    "port": 8443,
    "authentication": "bearer",
    "server_ca": "/private/provider-ca.pem",
    "credential_file": "/private/provider-credential",
    "audit_file": "/private/provider-audit.jsonl"
  }
}
```

The signing seed and outer AES key are separate 32-byte raw private files.
`subject` is required in provider mode. All inputs are host-selected private
files/directories; no guest request can choose them. CA and issuer state are
pinned for the foreground process, so trust rotation requires a coordinated
restart. Provider and local-broker configuration cannot be mixed, and a failed
provider setup never falls back to the local broker.

Run the same `garrett-bridge --config /private/bridge.json` and
`garrett-client --config /private/client.json` executables. The provider
readiness frame contains the bound `capability`, profile and expiry. Supply
that capability in a version-1 frame with request
`{"operation":"profile.read","arguments":{}}`.
Both explicit software and TPM client modes work; TPM provenance still needs
the independent enrollment checks documented in the Garrett guide.

The reproducible `dev/verification/garrett.py` gate includes provider tests,
HTTP framing tests, Lean obligations and Rust security mutations. Tests use
synthetic credentials and actual local TLS services, including the full
TPM-client/Rust-custody/provider path. No live accounts are contacted.

## Local validation

The full suite passed with **1,899 tests and one expected pending full-primitive
runner skip** in 289.00 seconds. The selected Garrett gate passed 62 tests;
the normal client/bridge builds passed all 22 integration tests. Lean checked
45 named obligations with the permitted axiom inventory. All fourteen changes to
actual Rust were re-extracted and rejected by the unchanged proofs, including
wrong-route substitution, a private-response-length disclosure and bypassed
composed authorization/audit linkage. The provider
cases also inspect service/client stdout, stderr, readiness fields and audit
records for credential leakage. Strict lint passes with and without the
conformance feature. These are local checks; hosted CI and physical TPM
validation remain unexecuted.
