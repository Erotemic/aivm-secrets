# Rust Garrett protocol and conditional Lean guarantees

The Rust implementation now issues and verifies the existing nested Garrett
surrogate, performs real TLS 1.3 client authentication, and forwards a permitted
action to the independent local broker. The client can sign inside a TPM.
Lean checks the extracted issuance/opening controllers and a separate symbolic
secrecy model. **This is experimental, unaudited work, not verification of the
entire service or a production approval.**

The useful conditional result is: an agent can use an authorized action without
receiving its provider credential; copying its surrogate does not grant another
client that authority. This requires an authentic TLS peer, protected host keys,
no access to the victim's signing oracle, and a provider response policy that
does not disclose credentials. The exact limits below are part of the result.

## Implemented path

```text
trusted host enrollment + inner aivs1 capability
  -> extracted Rust issuance controller
  -> Ed25519-signed, AES-256-GCM-encrypted certificate-bound surrogate
  -> agent's Rust TLS client (software or explicit TPM signer)
  -> Rust TLS bridge obtains the certificate from the completed handshake
  -> fresh enrollment lookup + extracted verification/binding/opening controller
  -> original version-1 broker.sock authorization and provider executor
  -> permitted public reply
```

The production controller is
[`aivm-secrets-garrett-core`](../rust/crates/aivm-secrets-garrett-core/src/lib.rs).
The independent adapters are
[`aivm-secrets-garrett`](../rust/crates/aivm-secrets-garrett/src/lib.rs):

- Exact canonical ASCII JSON, strict base64url, duplicate-key rejection,
  integer/Boolean distinctions and bounded streaming inputs.
- Current Python Ed25519/JWS and AES-GCM wire format, associated-data domain,
  key ID, certificate thumbprint, and authenticated inner `aivs1` envelope.
- TLS 1.3 only, required client certificates, server-name verification, no
  resumption/early data, hard exchange deadlines, bounded workers and frames.
- Opaque authenticated peer evidence; request fields cannot supply identity.
  Delegation is refused because an unbound child capability would escape the
  certificate boundary. No automatic retry after uncertain dispatch.
- Independent enrollment/renewal/revocation/CAS, trust-generation, key-rotation,
  VM-subject and OAuth transition functions with Python parity gates.
- Private host paths, ownership/mode checks, no final-component symlinks,
  private local broker socket, and restricted diagnostic error codes.

These are independent Rust decisions and cryptographic/transport adapters.
In the original bridge profile, the Python broker still performs inner-capability
authorization, credential
custody, audit, and provider effects. The Rust transition runners are not a
replacement for its durable authority service, OAuth vault, CA or provider
HTTP adapters. The explicit [account-status-v1 profile](verified-provider.md)
adds Rust-owned credential use, a pinned provider path and a proved typed
release projection for `profile.read`. Neither Python packaging nor ordinary
AIVM requires Rust,
Lean, TPM, a broker process, or this optional identity path.

## What Lean checks

[`Garrett.lean`](../proofs/Garrett.lean) proves properties of the actual Rust
core translated by pinned Charon/Aeneas, including real byte-vector equality:

| Property | Scope |
| --- | --- |
| Presentation accepts exactly the declared bindings | Issuer, audience, subject, actual peer thumbprint, current epoch and half-open lifetime |
| Stolen surrogate fails under another peer | No independent use without authentication as the bound certificate; assumes no victim signing oracle |
| Unbound inputs are rejected before unsealing | Exact production controller, independently of what the decrypt adapter would return |
| Successful opening has authenticated, bound claims | Explicit signature/decryption contracts, not client-supplied authentication flags |
| Issuance selects the enrollment's identity and lifetime | Inactive enrollments never reach sealing; expiration cannot outlive enrollment |
| Correct issuance/opening can succeed | Concrete valid-input witnesses and conditional successful-adapter composition; prevents an always-deny result |

[`GarrettSecrecy.lean`](../proofs/GarrettSecrecy.lean) is a **separate ideal
cryptography model**. It proves that no adaptive finite protocol trace can
derive a protected provider credential from public replies, nested encrypted
surrogates, attacker keys, or messages constructed using prior knowledge.
Ciphertext may publicly contain encrypted credentials. The model permits
signature/pair inspection and decryption with a known key.

The model does not establish that a real provider's response is safe: its
public-result projection is an explicit assumption. It does not prove
observational equivalence, hide metadata/length/timing, or refine the entire
Rust I/O system into the symbolic trace. Concrete cryptographic primitives,
TLS/X.509, parser, filesystem, compiler and translation are trusted boundaries.

The manifest now declares **65 named obligations**, including supporting lemmas,
the [credential-use/release contracts](verified-provider.md) and the
[composed request controller](verified-composition.md). The composition checks
authenticated opening, current inner authorization, exact audit acknowledgement
and selected provider execution in the native Rust request path. The
[history layer](verified-history.md) adds recorded issuance, ideal protected
signature origin and conditional source-controller histories.
The [certificate enrollment layer](verified-enrollment.md) checks exact CSR/key
approval binding before real Rust client-certificate signing.
Every transitive axiom dependency is checked afresh. Only Lean's `propext`,
`Classical.choice`, and `Quot.sound` are permitted; no admitted proof or
project-specific security axiom is allowed. Twenty-two deliberate changes to actual
Rust must break the unchanged extracted proofs: missing certificate binding,
missing epoch binding, inclusive expiry, inactive issuance, bypassing binding
before decryption, returning a token without sealing, removing inner binding,
bypassing use authorization, substituting a provider route and exposing private
response length in a public field. The composed-controller mutations also bypass
authorization or audit acknowledgement, substitute the recorded identity and
change the dispatched route.
The issuance mutations omit acknowledgement or record a different identity
before releasing the token.
Enrollment mutations bypass approvals, substitute the client key, exceed CA
validity or escalate software approval to a TPM label.

## TPM custody and enrollment evidence

[`tpm.rs`](../rust/crates/aivm-secrets-garrett/src/tpm.rs) implements an explicit
P256 ECDSA/SHA256 signer through fixed `/usr/bin/tpm2_readpublic` and
`/usr/bin/tpm2_sign` executables. It
accepts a pinned SHA256 TPMT_PUBLIC signing profile with `fixedTPM`,
`fixedParent`, `sensitiveDataOrigin`, and `userWithAuth`; it rejects imported,
decrypting, restricted or differently parameterized identity keys. It checks
the loaded public area, certificate/SPKI equality and every returned signature.
Key authorization uses private files, never literal argument values. A failed
TPM operation never selects a software key. Tool processes have bounded
deadlines and a cleared environment.

[`attestation.rs`](../rust/crates/aivm-secrets-garrett/src/attestation.rs) checks
TPM2 creation evidence under an **independently trusted restricted AK pin**.
It generates a fresh, expiring, consuming enrollment challenge; checks the
signature, qualified signer, generated magic, creation statement type, exact
challenge and key Name derived from the approved public area; and returns
opaque verified public-key evidence. A CA integration must bind that exact
SPKI to the enrolled subject and certificate. Client-provided AKs and a JSON
`tpm_backed` assertion are not trusted enrollment evidence.

TPM2-tools describes the underlying
[creation attestation](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_certifycreation.1.md)
and [signing operation](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_sign.1/).
Tests use isolated **software TPMs**, not physical silicon. They perform real
creation attestation and TLS signing without exporting the identity key, then
check wrong authorization, stale challenge, wrong key/AK, tampering and unsafe
attributes. The emulator host can copy state; this is not hardware custody.

Still required for a hardware deployment: independently authenticate the AK
(for example through EK credential activation and an approved EK trust policy),
choose physical versus virtual TPM ownership, enforce signing-oracle access,
and decide PCR/firmware and rollback policy. Those are not implied by key
attributes, this API, TLS, or the Lean theorems. No physical TPM was available
for this validation.

## Build and reproduce

Use the project's Python test environment and Linux x86_64 tooling documented
in [verified freshness](verified-freshness.md). The complete Garrett gate also
requires `swtpm` and `tpm2-tools`; its TPM tests must not skip.

```bash
sudo apt-get install --no-install-recommends swtpm tpm2-tools
.venv/bin/python dev/verification/garrett.py bootstrap
.venv/bin/python dev/verification/garrett.py check
.venv/bin/python dev/verification/garrett.py mutate
```

`check` validates the complete source inventory and pinned tools/models,
regenerates Lean byte-for-byte, builds proofs, audits all named obligations,
runs Rust formatting/Clippy, builds optimized executables, and runs independent
Python parity, real crypto, TLS/broker and TPM tests. `mutate` re-extracts and
compiles changed Rust before requiring the proofs to fail. CI runs both.
Hosted CI remains unexecuted until these changes are pushed.

After a reviewed change, update proofs/tests and run `garrett.py record`.
If a shared Cargo/Lake input changes, also reproduce and record the existing
freshness gate first. `record` requires extraction, proofs, lint and parity
to succeed before recording hashes; editing a manifest alone is insufficient.

## Initial identity-path validation

The initial identity-path checkpoint's Python suite passed with **1,887 tests
and one skip** in
280.05 seconds, with all implemented Rust runners selected. The remaining
skip is the unimplemented full primitive runner, not a Garrett gate. The
selected Garrett gate passed 50 tests. All ten integration tests also passed
using client/bridge executables built without the conformance feature.
Lean checked all 23 named obligations and every permitted axiom dependency;
all six re-extracted Rust mutations failed the proofs. Formatting and strict
Clippy passed with and without the conformance feature. Python source/wheel
packaging is verified separately from Rust binaries; hosted CI has not run.

## Foreground development executables

Build with `cd rust && cargo build --locked --release -p aivm-secrets-garrett`.
`garrett-bridge --config /absolute/private/bridge.json` starts a private Unix
TLS listener and reports a version-1 readiness frame. Configuration fields are:

```json
{
  "schema": 1,
  "issuer": "aivm.test", "audience": "aivm-secrets.remote", "subject": "vm-test",
  "listen": "/private/identity.sock", "broker_socket": "/private/broker/broker.sock",
  "registry_path": "/private/registry.json",
  "server_certificate": "/private/server.pem", "server_key": "/private/server.key",
  "client_ca": "/private/ca.pem", "kid": "test-1",
  "public_key_hex": "<64 lowercase hex digits>",
  "encryption_key_file": "/private/outer-key.bin"
}
```

`subject` is optional. All paths are operator-selected and must be private;
the outer key file contains exactly 32 raw bytes. The bridge reloads the
atomically replaced enrollment registry before each dispatch and fails closed
on missing/invalid state. An already admitted request may finish after a file
revocation; this is not a transaction spanning enrollment and provider effects.
The library's in-memory revocation lock gives a stronger local boundary only
when file-backed state is not selected. Server CA and issuer keys are pinned
for the process lifetime: coordinated trust rotation requires stopping/restarting
the bridge. It must not continue under a revoked trust generation.

`garrett-client --config /absolute/private/client.json` reads one version-1
frame from stdin and returns the public reply. Software mode has fields
`schema`, `socket`, `server_name`, `certificate`, `server_ca`,
`key_mode: "software"`, and `private_key`. TPM mode uses `key_mode: "tpm2"`
and replaces `private_key` with `tcti`, `persistent_handle`,
`authorization_file`, `public_area_file`, and `work_directory`.
TCTI must be `device:/dev/tpmrm0`, `device:/dev/tpm0`, or an explicit
`swtpm:path=/absolute/private/tpm.sock`. The handle is a persistent TPM handle
encoded as a JSON integer; authorization is 16–32 raw bytes; the pinned public
area is TPMT_PUBLIC, not a PEM file. Work files are removed after use.

The `--test-crypto` JSONL interface exists only when built with the development
`conformance` feature. It accepts synthetic keys and can reveal fixture
plaintext for interoperability testing. Never expose it as a service or feed
it live credentials. Normal bridge/client builds have no such endpoint.

## Remaining assurance work

The [acceptance plan](planning/aivm-secrets-garrett-verification.md) remains
the broader goal. Remaining work includes concrete adapter refinement,
durable authority/CA/trust cutover in Rust, TPM provenance deployment, broader
provider release/egress proofs, audit/log confinement, and a composed finite
service-history theorem. The extracted request composition does not establish
that whole-service result.
The full Rust primitive-runner gate also remains pending. Passing enumerated
parity cases is not a proof of Python/Rust equivalence on all inputs.
