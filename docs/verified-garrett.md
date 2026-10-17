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
replacement for its complete authority service, OAuth vault or provider
HTTP adapters. The native authority subset described below adds actual
durable initialization, enrollment, renewal and revocation. The explicit [account-status-v1 profile](verified-provider.md)
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

The manifest now declares **99 named obligations**, including supporting lemmas,
the [credential-use/release contracts](verified-provider.md) and the
[composed request controller](verified-composition.md). The composition checks
authenticated opening, current inner authorization, exact audit acknowledgement
and selected provider execution in the native Rust request path. The
[history layer](verified-history.md) adds recorded issuance, ideal protected
signature origin and conditional source-controller histories.
The [certificate enrollment layer](verified-enrollment.md) checks exact CSR/key
approval binding before real Rust client-certificate signing.
[`GarrettAuthority.lean`](../proofs/GarrettAuthority.lean) adds current-peer,
TPM-assurance, revocation and ordered durable-publication contracts for the
actual Rust authority controller.
[`GarrettTrust.lean`](../proofs/GarrettTrust.lean) adds exact trust-root fencing,
recovery-prefix and ordered retirement-before-activation contracts. The native
file issuer uses the existing extracted acknowledged-issuance controller.
Every transitive axiom dependency is checked afresh. Only Lean's `propext`,
`Classical.choice`, and `Quot.sound` are permitted; no admitted proof or
project-specific security axiom is allowed. Thirty-eight deliberate changes to actual
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
Authority mutations remove peer/expiry checks, escalate software assurance,
leave a revoked client active, bypass intent/material/publication steps, or
misreport a failure after publication as an unchanged store.
Trust mutations accept changed roots/enrollments, allow activation with old
enrollments, skip staging or retirement, activate before retirement, or report
an uncertain trust change as unchanged.

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

## Native authority and live admission

`garrett-authority` is a normal Rust executable, built without the conformance
feature. Its version-1 process interface accepts a private host request file:

```bash
garrett-authority init --root /private/authority --request /private/init.json
garrett-authority enroll --root /private/authority --request /private/enroll.json
garrett-authority status --root /private/authority
```

`init.json` contains `issuer` and `audience`. An enrollment request contains
`subject`, an absolute private `csr_file`, and `approve_fingerprint` (the
operator-confirmed SHA-256 SPKI fingerprint). Requests can select `now` for
trusted host testing; ordinary operation uses the host clock. Replies are
`{"version":1,"ok":true,"result":...}` or a fixed error code. No private
key is a reply, diagnostic or command argument. The executable writes CA,
server and issuer keys only into the protected authority store.

Implemented actions are `init`, `status`, `enroll`, `renew`, `enroll-tpm`,
`renew-tpm`, `public-client`, `revoke`, `revoke-if-current`, `forget` and
`prune`. Native lifecycle/file actions are described below. Renewal requires `expected_epoch` and `expected_thumbprint`;
`require_new_key` selects rekeying. Enrollment replacement requires explicit
`replace`; its optional compare-and-swap needs both expected values.
Stale conditional revocation returns `revoked:false`, as in the reference.
The Python v2 authority/registry/key formats are retained with no migration.
Python can read/sign using Rust-created keys and enrollments, and Rust can
open Python-created authorities. Ed25519 private/public material follows
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html).

For TPM enrollment, replace `approve_fingerprint` with independently provisioned
private `ak_public_area_file` and `ak_qualified_name_file` paths. The executable
emits a fresh 120-second challenge (`challenge_hex`), then reads exactly one
bounded version-1 evidence frame with `public_area_hex`, `attestation_hex`,
and `signature_hex` from stdin. It verifies creation evidence and CSR key
equality before signing. The challenge deadline is rechecked after acquiring
the authority lock. Client JSON cannot supply an AK trust decision or
`tpm_backed` assertion.

New enrollments write a private immutable assurance receipt next to the public
certificate. It binds subject, certificate thumbprint, SPKI fingerprint,
assurance mode and issuance time; TPM receipts also name the trusted AK pin
digest and certified key Name. Missing receipts mean unrecorded assurance.
The Rust administrator refuses software replacement of a recorded TPM client
unless the host explicitly selects `allow_assurance_downgrade`. Older Python
administrators do not enforce this new policy; use the Rust administrator when
requiring it. Host administrators remain trusted and can modify their store.

The authority holds no-symlink directory descriptors, checks private ownership
and regular single-link files, and uses the common `.enrollment.lock` inode.
Initialization builds a private staging directory, writes its manifest last,
then publishes with `RENAME_NOREPLACE`; it never resets/adopts an existing
target. Enrollment persists an audit intent, immutable leaf and receipt before
atomically publishing the registry, then records completion. A failure during
or after publication returns `outcome_unknown`; it never promises unchanged
authority. Staged files and intent coordinates survive failures for inspection.
These are adapter contracts: [rename](https://man7.org/linux/man-pages/man2/rename.2.html)
and [file/directory fsync](https://man7.org/linux/man-pages/man2/fsync.2.html)
semantics and the host filesystem are trusted. Explicit trust-transaction
recovery is described below; snapshot rollback protection is not implemented.
The hash chain cannot detect tail truncation
without an externally anchored head.

The bridge can instead select this held authority as its complete trust source:

```json
{
  "schema": 1,
  "authority_root": "/private/authority",
  "client_assurance": "attested-tpm",
  "subject": "vm-test",
  "listen": "/private/identity.sock",
  "broker_socket": "/private/broker/broker.sock"
}
```

Use `any-enrolled` to deliberately permit software/unrecorded enrollment.
For native custody, replace `broker_socket` with the `provider`, `binding` and
`lifetime` fields in the [provider profile](verified-provider.md). Trust/key/TLS
paths come from the held authority and cannot be mixed with independent legacy
fields. TPM-required issuance fails before custody/session creation for a
software or missing receipt. Each request reloads the enabled issuer keyring
and enrollment, and fences CA changes. Enabled old signing keys still work;
retired keys do not. A root change makes the old bridge refuse dispatch and
requires an explicit restart with the new trust material.

Native admission holds a shared authority lease through provider use or broker
forwarding. Participating administrators take the exclusive lease, so a
successful revocation waits for already admitted operations to finish and
prevents later admission. This is tested with a blocked real provider request;
it does not cancel already sent effects. The independent-file bridge described
above retains its older snapshot behavior. Lock starvation, host compromise,
nonparticipating writers and complete concurrent I/O/history refinement are
outside the Lean result.

Sixteen new named obligations check the actual admission/revocation and
commit controllers, including positive witnesses. Successful commit requires
intent, staging, publication and completion in order under explicit adapter
contracts. Failures before publication bypass publication; publication or
completion failures report uncertainty. The proofs do not assert that Linux,
the storage adapter, TLS or the audit file is itself formally verified.

The earlier native authority checkpoint passed **1,930 full-suite tests**, with the
one expected pending general primitive-runner skip (285.16 seconds), and
**93 selected Garrett tests**. All **81 named obligations** pass the transitive
axiom audit. The **18 new authority tests** also pass with normal executables
built without conformance features, including real software-TPM enrollment,
TLS signing/provider use, replay refusal, live trust changes, revocation drain,
expiry after waiting on a lease and partial-write outcomes. These remain
software-TPM results; hosted CI and physical TPM validation have not run.

## Native trust rotation, recovery and file issuance

The normal administrator also implements `rotate-issuer`, `retire-issuer`,
`renew-server`, `rotate-ca`, `transactions`, `transaction-status`, `recover`
and `issue`. Issuer rotation installs a fresh Ed25519/AES key set before
switching the keyring; enabled older keys remain usable until explicit
retirement. `retire-issuer` requires `kid` and refuses the active key. Failed
immutable names are preserved and skipped by future allocations. No private
key is silently adopted, overwritten or deleted. Server renewal stages a new
server-only leaf under the current root and reports `restart_required:true`.

`rotate-ca` requires the operator's `expected_ca_sha256`. A stale expectation
fails before staging, audit or enrollment writes. The native source controller
performs intent → complete material staging → durable retirement of all
enrollments → trust activation → completion acknowledgement. Retirement itself
changes authority: a failure from that point returns `outcome_unknown`.
The registry and selector are separate durable publications. A crash can leave
the old root with retired enrollments; recovery moves forward from that state.
Running old-root brokers fence themselves on their next admission. The operator
must redistribute the public root, re-enroll clients and restart TLS contexts.

Each trust change persists a private `transactions/<id>/plan.json` before
effects. It contains closed-schema public snapshots, approved immutable file
names, public certificate/key digests, operation and timestamp. It contains no
private-key/AES bytes or hashes of those secrets. Audit intent anchors that
public plan's digest. Private staged keys must match their public certificates
or signing keys; the AES file must have the exact supported length. Integrity
of the private store and entropy source remain assumptions.

Use `transactions` to locate preserved plans and `transaction-status` with
`transaction` to inspect one. Listing reports partially written plans as
`invalid-plan` without hiding other transactions. Recovery requires
`transaction` and `expected_plan_sha256`, rather than selecting a plan or
retrying a failed operation automatically. It checks complete material and
the exact current authority/keyring/enrollment prefix under the exclusive
lease. Only unchanged, retired or fully activated prefixes are admitted.
New enrollments, later trust changes and activation with an old registry
conflict; recovery cannot restore an old registry or revoke newly enrolled
clients. Incomplete/corrupt private material is refused without repair.
Expired staged certificate plans are refused. Replaying a fully activated plan
with unchanged state performs no pointer rewrite and records reconciliation.
These recovery actions cover the new trust transactions; earlier enrollment
and issued-output failures retain their existing coordinates for inspection.

The eighteen new obligations include exact byte-vector root fencing and
recovery classification, refusal of changed enrollment snapshots, successful
prefix witnesses, stale-CAS refusal before effects, and conditional ordered
staging/retirement/activation/completion. Storage contracts are hypotheses,
not project security axioms. Tests reconstruct interruption prefixes using
real native staged material and inject failures around the real filesystem
adapters; they do not simulate a disk power loss or prove Linux lock/fsync
semantics. Concrete concurrent service/history refinement remains open.

`issue` accepts private host-file paths instead of literal capabilities:

```json
{
  "subject": "vm-test",
  "inner_capability_file": "/private/inner.capability",
  "output": "/private/issued.jwt",
  "client_assurance": "attested-tpm",
  "lifetime": 900
}
```

Use `any-enrolled` only when permitting software/unrecorded enrollment.
The current row, assurance and enabled issuer are checked under a shared
authority lease. The extracted recorded-issuance controller binds the token
to that enrollment and acknowledges its exact public identity before the
native adapter publishes a complete protected file with no replacement.
No raw capability/token is returned in the administrative reply or audit.
Replies contain public subject/expiry/thumbprint and output coordinates.
Delivery to the agent remains explicit. Existing destinations are refused;
partial stages are retained, and publication/completion uncertainty is never
treated as permission to overwrite/retry. This path is interoperable with the
reference Python verifier and the normal Rust authority-backed TLS bridge.
Once rename is attempted, errors conservatively report uncertainty. Linux's
[rename documentation](https://man7.org/linux/man-pages/man2/rename.2.html#BUGS)
describes failed acknowledgements after completed NFS renames; an error alone
cannot establish that publication did not occur.

The lifecycle/file checkpoint passes **1,949 full-suite tests** and the one
expected pending general primitive-runner skip (285.88 seconds), using normal
authority/client/bridge binaries. Its recorded gate passes **112 selected
Garrett tests**, all **99 named axiom checks**, strict Rust lint in both build
modes, and five Rust unit checks. Nineteen new Python tests cover lifecycle,
recovery and issuance through the actual executables and independent reference
readers. The hardware-path tests require software TPM execution and do not
establish physical hardware provenance. Hosted CI remains unexecuted.

## Remaining assurance work

The [acceptance plan](planning/aivm-secrets-garrett-verification.md) remains
the broader goal. Remaining work includes concrete adapter refinement,
complete credential/policy and OAuth custody in Rust, TPM provenance deployment, broader
provider release/egress proofs, audit/log confinement, and a composed finite
service-history theorem. The extracted request composition does not establish
that whole-service result.
The full Rust primitive-runner gate also remains pending. Passing enumerated
parity cases is not a proof of Python/Rust equivalence on all inputs.
