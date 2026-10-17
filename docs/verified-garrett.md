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
replacement for its general policy interpreter. The native OAuth subset below
adds encrypted custody, HTTPS refresh and dispatch leases; the native authority subset adds actual
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

The manifest now declares **139 named obligations**, including supporting lemmas,
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
[`GarrettOAuth.lean`](../proofs/GarrettOAuth.lean) adds exact refresh eligibility,
not-sent/uncertain/rejected settlement, epoch/generation/expiry lease fencing,
and the ordered quarantine/exchange/commit controller contract.
[`GarrettLogin.lean`](../proofs/GarrettLogin.lean) adds exact callback state,
issuer and time binding, one-shot claim/exchange transitions, terminal-state
replay rejection and successful-acquisition witnesses.
Every transitive axiom dependency is checked afresh. Only Lean's `propext`,
`Classical.choice`, and `Quot.sound` are permitted; no admitted proof or
project-specific security axiom is allowed. Fifty-nine deliberate changes to actual
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
OAuth mutations remove quarantine or successor persistence, exchange before
quarantine, permit silent retry or rejected-grant reuse, clear prior doubt after
a failed deliberate retry, or admit stale/expired credential leases. Login mutations bypass callback state/issuer
binding, accept expired or consumed callbacks, exchange without admission or
more than once, treat a denial as a code, or complete before exchange/storage.

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

## Native OAuth custody and refresh

`garrett-oauth` is a normal host-only executable with `init`, `enroll`, `status`,
`revoke`, `refresh` and `session-check` actions. Build it without fixture APIs:

```bash
cd rust
cargo build --locked --release -p aivm-secrets-garrett --no-default-features --bin garrett-oauth
cd ..
rust/target/release/garrett-oauth init --root /private/oauth-vault
rust/target/release/garrett-oauth enroll --root /private/oauth-vault --request /private/enroll.json
rust/target/release/garrett-oauth refresh --root /private/oauth-vault --request /private/refresh.json
```

Requests are private host files. Enrollment takes `provider_file`, `subject`
and `grant_file`, with optional explicit `replace`. The grant file uses the
reference fields `access_token`, `refresh_token`, `expires_at`, `scopes` and
`generation`. It remains a secret-bearing operator input; enrollment does not
remove that file. Refresh takes `provider_file` and `subject`, with optional
explicit `retry_in_doubt`. Responses and schema-2 chained audit files contain
metadata and fixed errors, never grant tokens or token-endpoint bodies.
Normally omit `now`; the host executable supplies its clock. Its explicit
clock override is a trusted host input for reproducible tests.

The native vault reads and writes the reference AES-256-GCM record/AAD format
and canonical provider digest. Python can read native records and native code
can read Python records. Provider changes prevent use, while inspection,
revocation and explicit replacement can adopt the authenticated old record
with an incremented epoch and previous-digest prefix. Root/key/lock/record
operations use held directories and no-symlink file descriptors. Initialization
publishes a complete private directory without replacing an existing root.

The actual Rust refresh controller requires acknowledged intent and durable
`in_doubt` storage before calling the private HTTPS adapter. The adapter checks
the pinned origin's certificate before request bytes, disables resumption and
early data, and has bounded connect/exchange/body handling. It supports TLS
1.2/1.3 for OAuth providers; the identity channel and account-status provider
remain TLS 1.3 only. It follows no redirects and reads neither proxy nor TLS
key-log/trust overrides from the environment. Default trust comes from fixed
Linux system CA locations. An explicit host `transport` object may select a
`server_ca`, `address` and `port` for a private/synthetic endpoint; certificate
name and HTTP origin still come from the approved provider profile.

A validated rotated successor must be persisted before the controller returns
it. Scope expansion, malformed replies, redirects, lost responses and uncertain
writes never silently restore the old ready grant. A definite `not_sent`
restores the **exact prior state**, so a failed deliberate retry remains in
doubt. HTTP 400 `invalid_grant` requires reauthorization; even explicit retry
cannot override that state. A failed rename acknowledgement can leave either
the marker or the committed successor: the caller receives uncertainty, and
neither outcome authorizes automatic reuse of the old refresh token. Process
death after the request leaves a durable marker and an unmatched audit intent.

The account-status-v1 broker configuration accepts exactly one of
`credential_file` or an `oauth` object:

```json
{
  "vault_root": "/private/oauth-vault",
  "provider_file": "/private/provider.json",
  "subject": "vm-test"
}
```

The OAuth source requires bearer authentication and the exact approved resource
host. It may refresh near expiration, then retains a private snapshot and HMAC
witness of the token plus profile/account/epoch/generation/expiry. Each issuance,
control operation and provider request checks a current vault record under a
lease; provider requests retain that lease through egress. Admission samples
wall time again after waiting on the vault lock, including waits that cross an
expiry boundary in less than one second. Refresh and revocation
wait for admitted calls to finish, and completed changes fence older sessions.
Even token replacement with unchanged public metadata fails the HMAC check.
An unavailable or invalid vault never selects a credential-file fallback.

The native OAuth checkpoint passes **1,975 full-suite tests**, with the one
expected pending general Rust primitive-runner skip (279.26 seconds), using
normal authority/client/bridge/OAuth binaries. Its recorded gate passes
**138 selected Garrett tests**, all **121 named axiom checks**, strict Rust
lint in both build modes and six Rust unit checks. The **26 new OAuth cases**
cover cross-language ciphertext, real local HTTPS, process death, failed
successor persistence, concurrent refresh, profile adoption, draining revocation,
stale tokens and subsecond expiry after a blocked admission.

The Lean result is conditional on the stated storage, audit, transport and
cryptographic adapter contracts. It proves the ordering in the extracted Rust
controller; it does not prove AES-GCM, HMAC, rustls, kernel locks, fsync, parsing
or arbitrary concurrent service executions. The native login path below adds
actual loopback callback and code exchange with extracted lifecycle guards.
Host compromise, snapshot rollback, nonparticipating writers and provider
disclosure remain outside this result. No live OAuth account or physical TPM
was used.

## Native authorization-code acquisition

The normal `garrett-oauth login` command now obtains a grant without a plaintext
grant input file. Its private host request contains `provider_file`, `subject`,
optional explicit `replace`, `timeout` (1..600 seconds, default 180), and the
same optional pinned `transport` object used for refresh:

```json
{
  "provider_file": "/private/provider.json",
  "subject": "vm-test",
  "timeout": 180
}
```

```bash
rust/target/release/garrett-oauth login --root /private/oauth-vault --request /private/login.json
```

After a read-only enrollment preflight and transport preparation, the command
creates fresh state and PKCE verifier entropy, binds only `127.0.0.1` at the
profile's callback port, then emits a version-1 `authorization_required` JSON
event with `authorization_url` and `expires_at`. Open that URL in a trusted
host browser, as with the reference CLI. This is a host-only interactive event,
not an agent operation: the state and challenge are intentionally shared with
the operator/browser and must not be offered through a guest or remote agent
API. The private verifier is represented only by its S256 challenge in that URL.
No shell/browser command or browser executable supplied by a callback is run.

The receiver requires the exact local Host and `/oauth/callback` target,
bounded ordinary HTTP, unique query fields, matching state, the profile's exact
optional issuer rule and the half-open pending lifetime. Wrong or malformed
callbacks keep the login waiting. A matching denial consumes the pending flow
and terminates with fixed `authorization_denied`; provider descriptions/URIs
are never echoed or fetched. Idle and trickling clients are cut by an absolute
five-second request deadline bounded by the whole login deadline. The flow's
state is consumed before acknowledging a valid callback; a failed browser
acknowledgement does not reopen it. The listener closes before token exchange,
so queued or replayed callbacks cannot cause another redemption.

The actual Rust controller rechecks the clock before beginning exchange and
enters a state that cannot begin again. It posts only the approved client ID,
accepted code, fixed redirect URI, private verifier and optional host-held
client secret to the pinned token origin. It never redirects, exports the code
or verifier in CLI replies/audit, or retries the code automatically. The native
authorization URL is checked byte for byte against the independent Python
constructor using the verifier observed only at the synthetic HTTPS endpoint.
The callback, denial, uncertain, complete and consumed transitions come from
the Aeneas-extracted core; HTTP/query decoding, entropy, SHA-256 and I/O order
remain explicit adapter obligations.

A validated initial grant installs through the same encrypted-vault transaction
as import. Enrollment is checked again under the vault lock, so another login
that wins during the browser wait is not overwritten without explicit
`replace`. Reauthorization advances the credential epoch and resets the new
grant generation. Only metadata is returned after successful installation.
The new grant is immediately usable by the native authority/provider path,
which releases only its declared `id`/`active` result.

`exchange_not_sent`, `exchange_rejected` and `exchange_in_doubt` distinguish
transport outcomes with fixed text. A valid grant that cannot be installed
reports `grant_orphaned_upstream` with the storage/enrollment error code. A
failed publication acknowledgement may already have installed it; inspect the
vault before further action. A killed login may leave a grant upstream with
no local record: state, verifier and code are process-local and there is no
automatic resumption. Enrollment audit starts at installation; a concrete
acquisition audit/history refinement remains open. No live browser account,
external OAuth provider, managed VM or physical TPM was used in these tests.

The native login checkpoint passes **2,008 full-suite tests**, with the one
expected pending general primitive-runner skip (300.52 seconds), using normal
native service binaries. The recorded gate passes **171 selected Garrett tests**,
all **139 named axiom checks**, strict Rust lint in both modes and six Rust
unit checks. **33 new login tests** exercise the real callback/code-exchange
path and an independent Python URL/ciphertext oracle. The mutation gate now
requires 59 changed Rust controllers to fail unchanged proofs, including eleven
new callback/lifecycle attacks. Hosted CI remains unexecuted.

## Native declarative provider execution

`manifest-https-v1` extends the native custody path to a host-selected schema-2
HTTPS policy. The provider receives the real credential while the authenticated
agent sends only an operation name and bounded scalar arguments. Implemented
semantics include integer sets/ranges and string allowlists, path/query templates,
body fields, aggregate UTF-8 body limits, defaults and ASCII folding, declared
read/write classification, checked facts and validated captures, fact returns,
pagination metadata and a fixed single named GraphQL query. A POST read is
allowed only for that static GraphQL form. The provider contract still determines
whether a declared read is actually non-mutating.

Select the new profile in the native bridge/authority configuration's `provider`
object, using host-owned files and the same mTLS/authority setup described above:

```json
{
  "profile": "manifest-https-v1",
  "host": "api.example.org",
  "address": "192.0.2.25",
  "port": 443,
  "authentication": "bearer",
  "server_ca": "/private/provider-ca.pem",
  "credential_file": "/private/provider-token",
  "audit_file": "/private/provider-audit.jsonl",
  "policy_file": "/private/tracker-policy.json",
  "disclosure_file": "/private/tracker-disclosure.json",
  "writes": "allow",
  "request_limit": "unbounded"
}
```

`writes` must explicitly be `allow` or `deny`; a GET declared as a write uses the
same gate as PATCH. There is no new quota: `request_limit: "unbounded"` explicitly
overrides the legacy policy's numeric `max_requests`. This is a versioned native
profile choice, not a silent reinterpretation of an existing session. The
policy's credential source must exactly name the selected file. For an OAuth
source, omit `credential_file`, supply the existing `oauth` object and explicitly
select `source_override: "oauth"`. There is no source fallback. Host, authentication
and any declared address/port/CA pins must agree. The effective policy digest
binds the native configuration, supplied policy document and disclosure document.
It is not the Python interpreter's normalized policy digest; omitted defaults
and explicitly supplied defaults may produce distinct native session digests.
Policy, disclosure and file credentials are session snapshots. Editing those
files does not revoke an existing session: renounce or stop/restart the service
when applying a policy/file-source change. Restart replaces the ephemeral inner
key and invalidates the old session's tokens. OAuth mutations instead participate
in the active credential lease described above.

For example, a reviewed operation can contain:

```json
{
  "name": "ticket.edit",
  "effect": "write",
  "method": "PATCH",
  "path": "/v1/tickets/{ticket}",
  "parameters": {"ticket": [7, 8]},
  "body_fields": {"text": 2000}
}
```

A disclosure document must name every operation exactly once and specify its
public fields. For this operation, a minimal entry is:

```json
{
  "ticket.edit": {
    "id": {"at": ["id"], "type": "integer"}
  }
}
```

Pointers traverse object keys. Types are `integer`, `boolean`, `text`, `null`,
`object` with a `fields` map, or `array` with `items` and bounded `max_items`.
Every object level drops undeclared fields. Selected copies are charged against
a reply-size bound before construction, including repeated projections. There is
no unrestricted JSON projection. Arrays apply their item schema recursively. Selected decoded text
and keys, serialized results and final route coordinates are checked against
literal credential reflection. A malicious provider reflecting the credential
in a captured path is rejected before that final route is logged or sent.
These checks do not establish that an allowed field cannot reveal a secret
through an encoding, fragment, timing channel or semantic information. The
operator/provider disclosure contract is still essential.

The native path holds its authority and optional OAuth credential lease through
both preflight and final execution. It rechecks identity and grant freshness
after preflight and after each acknowledged dispatch audit. Acknowledged audit intent precedes each effect, and bodies and
provider diagnostics are not logged. Calls use the configured IP and verified
TLS hostname, with no proxy environment, key log, redirect following or automatic
retry. Framing is bounded and rejects ambiguous/compressed responses. JSON
responses require the declared JSON media type; text responses require plain
text, with the usual empty 204 exception. Empty JSON is rejected. After any
attempted write, transport, provider, projection or completion-audit failure is
`outcome_unknown`; the action may already have happened. A connection/TLS failure
before sending remains `unreachable`. Read HTTP errors use fixed rejection/error
codes without provider text. HTTP status metadata is not preserved in the native
error envelope.

`GarrettManifest.lean` proves contracts over the Aeneas translation of the actual
Rust parameter and admission guards: exact allowlist membership at the checked
index, range/body authority, type mismatch and out-of-bounds denial, current grant
and exact operation/write permission. A broken or malicious search index cannot
make an unlisted value pass. Its release theorem states that changing discarded
response bytes cannot change already-selected output bytes. It does not prove
the JSON projection adapter, route/check/GraphQL parsers, actual network/audit
ordering or the whole service. `manifest-conformance` compares independently
compiled effects against Python; integration tests inspect real HTTPS methods,
targets, bodies and credential headers and exercise denial, expiry, revocation,
projection and uncertain-write paths. This is finite behavioral evidence, not an
all-input equivalence proof.

The native-manifest checkpoint passes **2,073 full-suite tests**, with one
expected pending general primitive-runner skip (305.91 seconds), using normal
native service binaries. The recorded gate passes **236 selected Garrett tests**,
all **154 named axiom checks**, strict Rust lint in both modes and six Rust
unit checks. **65 new manifest tests** cover independent Python effect compilation
and actual native provider I/O, filtering, expiry and revocation. The mutation
gate requires **70 changed Rust controllers** to fail unchanged proofs, including
eleven new parameter, operation/write and release attacks. Hosted CI remains
unexecuted, and all credentials/providers/TPM activity in this validation are
synthetic or isolated emulation.

A follow-up raw-number review found and fixed a route mismatch: arbitrary-
precision JSON preserved the spelling `-0`, membership guards interpreted it as
integer zero, and interpolation formerly produced `/-0`. Arguments and defaults
now normalize to the validated integer and routing renders that value. Numeric
facts compare integer values while preserving the distinction from floats,
booleans and strings. A custom TLS client regression reaches the broker without
the ordinary client's canonical encoder; only `/0` may be selected when integer
zero is approved, even when the synthetic provider exposes a different `/-0`.

The updated checkpoint passes **2,083 full-suite tests** with the same one
expected skip (315.33 seconds), **246 selected tests**, strict lint and six Rust
unit checks. **75 manifest tests** now include ten raw-number routing, default,
query and typed-fact cases. The extracted controller and proof sources remain
unchanged from the successful 70-mutation run; updated runtime/test hashes are
recorded. The subsequent recursive-disclosure refinement is isolated in a
worktree and is not part of this checkpoint's assurance claim.

Native CLI alias tables, command resolver execution, one-shot write approvals,
and delegated/attenuated grant lineages remain unfinished. Nonempty CLI tables
are explicitly rejected. Command source descriptions are validated by the pure
compiler but are not executed by a native session. Use a reviewed file source
or explicit OAuth override. Existing Python policies are not migrated or changed.

## Remaining assurance work

The [acceptance plan](planning/aivm-secrets-garrett-verification.md) remains
the broader goal. Remaining work includes concrete adapter refinement,
complete credential/policy administration, native client aliases/resolvers/approvals/delegation,
TPM provenance deployment, broader
provider release/egress proofs, audit/log confinement, and a composed finite
service-history theorem. The extracted request composition does not establish
that whole-service result.
The full Rust primitive-runner gate also remains pending. Passing enumerated
parity cases is not a proof of Python/Rust equivalence on all inputs.
