# Garrett issuance and dispatch histories

The native Rust provider now records the exact signed public identity before
releasing its surrogate. Dispatch records carry the same identity and
grant/policy identifiers. The extracted `issue_recorded` controller calls the
existing issuance controller, requires acknowledgement of that issuance record,
and only then returns the token. An audit failure releases no readiness frame
or token. Tokens remain reusable and named-operation authority is unchanged.

[`GarrettHistory.lean`](../proofs/GarrettHistory.lean) checks three related
boundaries. These are conditional results; concrete service-history refinement
remains open.

## Recorded issuance from the actual Rust controller

`recorded_issuance_contract` joins enrollment-selected claims, the exact sealed
token and acknowledgement of those same claims. Crypto and durable-record
adapters supply named contracts. Failure and success theorems cover rejected
and accepted acknowledgement. Native `ProviderSession::issue` uses this
controller; the separate legacy crypto/conformance issuance interface does not
participate in this provider history.

The file-size-limit test allows session-open to finish and interrupts the
issuance record after signing. It checks empty stdout, a closed error code,
an incomplete audit tail and no provider I/O. Existing audit behavior refuses
that incomplete tail on restart.

## Protected signature origin in the ideal cryptography model

`Garrett.History.Trace` retains honest issuer outputs separately from attacker
observations. An attacker can adaptively replay tokens, construct pairs,
inspect signatures, encrypt, decrypt with known keys and sign with known keys.
Only an issuance step adds an honest issuer output.

`protected_signature_was_issued` proves that every protected-key signature
deducible in any finite trace belongs to those issuer outputs. The proof uses
the existing key-confinement theorem rather than assuming signature origin.
Replaying or wrapping a signature does not issue it again. This ideal message
algebra does not prove computational Ed25519 unforgeability, encoding
injectivity, SHA-256 collision resistance or concrete verifier correctness.

## Conditional histories of the source controllers

`Garrett.ControllerHistory.Run` projects histories onto successful recorded
issuance and acknowledged dispatch boundaries. The rules require successful
extracted `issue_recorded` and `prepare` calls and acknowledgement of the exact
identity, inner claims, route and operation. They do not assume successful
presentation or authorization as premises.

The verification adapter has a named signature-origin contract: authenticated
token bytes and public claims match a prior recorded issuance. This is the
concrete crypto/history assumption whose ideal counterpart is proved above.
Unsealing and opening also have explicit partial-correctness contracts.
`all_histories_correspond` then derives, for every dispatch:

- Matching token and identity issuance in the strictly older history suffix.
- Exact issuer/audience/subject/peer/epoch/time binding.
- Current inner binding, policy, grant ID and lifetime checks.
- The exact allowed operation.

The correspondence is non-injective: repeated uses can refer to one issuance.
Failed admissions add no dispatch event to this projection.
`dispatch_continuation` connects acknowledgement to the actual Rust controller's
selected credential/route execution continuation, regardless of provider
success, error or divergence. A dispatch record expresses intent, not remote
effect completion. Private prepared credentials exist only in the mathematical
witness; the public audit representation does not serialize them.
The public audit stores claims rather than token bytes or a token hash. The
model's exact token witness comes from the source call's returned value; this
is not an offline validator deriving byte-level provenance from the audit file.

The model does not establish which concrete byte/filesystem histories satisfy
the origin contract, connect bytes to the ideal message algebra, or prove the
credential's complete acquisition/refresh history matches its earlier sealing.
The [request composition](verified-composition.md) separately retains named
envelope and inner-opening provenance contracts.

## Revocation and remaining scope

The service reads enrollment at request admission. A blocked-provider test
revokes enrollment after a request reaches the provider, lets it finish, then
checks another request is refused before a second effect. The theorem checks
supplied admission snapshots; registry-update linearization, rollback and
coordination with an independent administrator remain unproved.

The gate inventories 55 named obligations and 16 re-extracted Rust mutations,
including omitted and substituted issuance acknowledgement. Reproduction is
documented in [verified Garrett](verified-garrett.md). Full I/O refinement,
durable authority/CA/OAuth administration, general policy/provider support and
physical TPM provenance remain in the
[acceptance plan](planning/aivm-secrets-garrett-verification.md). The project
remains experimental and unaudited.

Local validation passed with 1,901 tests and one expected pending full-primitive
runner skip (288.32 seconds), 64 selected Garrett tests and 24 normal-build
integration tests. Hosted CI and physical TPM validation remain unexecuted.
