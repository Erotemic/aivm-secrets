# Status and work queue

The current state of `garrett-stateless` and what comes next, in order. The
dated notes from before the extraction are in [`history/`](history).

## State (2026-11-01)

Both implementations are complete for `garrett-stateless-v1`: the OAuth and
provisioned acquisition adapters, the broker, the stateless proxy with the
unrestricted and read-only operation policies, strict mode, key rotation and
retirement, and an optional TPM agent key. The Rust core is extracted to Lean
and proved; the composed internal theorem is `protocol_safety`, and
`composed_egress` covers both operation policies
([verification.md](verification.md)).

**Extraction from `aivm-secrets` (2026-10-29).** This tree was developed
inside `aivm-secrets` and is now self-contained:

- the core crate owns the HTTP/1.1, base64 and OAuth-login code it uses,
  forked from that project and pruned to what the protocol reaches (no
  function in it is unreachable from the protocol's own code);
- the proofs are their own Lake package; the supporting HTTP and OAuth proofs
  came with the code and were pruned to the lemmas the protocol proofs use;
- the Python reference is the `garrett_stateless.core` package, module for
  module as the Rust crate, with its own copy of the HTTP subset; the crypto
  calls moved behind the same `KeyMaterial`/`StateKey` interfaces as in Rust;
- the TPM signer was ported into `crates/garrett-stateless` (feature `tpm`);
- verification tooling, vectors, examples, the demo and the documentation
  moved here.

**Review of `a407644` (2026-10-29).** Acted on: the Lean imports follow the
protocol's concepts (generic lemmas in `GarrettFoundation`); `TokenSealer`
seals once and fixed-nonce sealing is test-only; the agent refuses a reply
without its limits; `open` is `authenticate` then `decrypt`; the
application's grammar checks call the core's; `stateless_token.rs` and
`proxy_http.rs` are split by responsibility; `proofs/Garrett.lean` states the
guarantees as named propositions and `Isolated` became `AuthorizedEgress`
with named parts; `PROTOCOL.md` and a compiled library example
(`crates/garrett-stateless/tests/library.rs`); the claims in the docs are
classified as proved, assumed, guarded or tested, or not established; the
refusal responses say `garrett-stateless` and the two codes only the old
project used are gone (a deliberate wire change: both implementations, the
refusal vectors and the refusal proofs together).

**Product-level guarantees (2026-11-01).** `proofs/Garrett.lean` now states
five guarantees — compromised-agent confinement, credential confidentiality,
bounded delegation, authorized acquisition and stateless authorization — as
named propositions over the extracted code, and `security_guarantees` proves
the per-execution ones for every reachable world. Behind them:

- each proxy `Route` carries its `Destination`; the extracted `exchange`
  connects to exactly the selected route's destination and writes only after
  the shell reports an authenticated session; the native proxy keeps no
  destination table, and `routes_valid` refuses two routes for one provider;
- the connection log records `connected D ok` and `sent D wire`; every write
  follows the authenticated connection to the destination of the
  surrogate's provider route (`send_origin`, `protocol_safety`);
- the network-level statement rests on one explicit trusted contract,
  `TransportFaithful`;
- `GarrettConfidentiality`: two-run theorems for the proxy's decision and
  reply and for issuance, with the declassification boundary in
  `STATELESS-DISCLOSURE-01`;
- new adversarial tests (impostor and untrusted-CA destinations over real
  TLS, failed connections and writes, bounded answers, an unrouted provider,
  audit and replies without the credential) and nine new mutants.

## Validation

At the commit that recorded this table (see `git log`):

| Check | Result |
| --- | --- |
| `cargo test` (core and application; also with `--features tpm`) | 59 pass |
| `python -m pytest` (including interop, replicas, operations, vectors, purity) | 120 pass |
| `verification/extract.py check` | pass; the model has no `axiom` |
| `lake build` (independent package) | pass (1821 jobs; cold, 303 s) |
| `verification/mutate.py` | all 51 rejected at `2e16f5a` (3047 s, `--jobs 10`, in the separate-directory copy): `GarrettStatelessProxy` 12, `GarrettStateless` 8, `GarrettStatelessComposition` 6, `GarrettStatelessMailbox` 6, `GarrettStatelessToken` 6, `GarrettStatelessGrammar` 4, `GarrettStatelessLogin` 4, `GarrettStatelessConnection` 2, `GarrettStatelessCodec` 1, `GarrettStatelessState` 1, `GarrettConfidentiality` 1 |
| `verification/shell_guard.py check` | pass (12 checks) |
| Separate-directory check (`verification/standalone.py`) | pass at `2e16f5a`: a copy of this directory alone, with a fresh virtual environment, Cargo target, toolchain bootstrap and cold Lake build, ran every row above; no source names the origin project outside the allowed history and provenance notes |

## Next, in order

1. **Typed identifiers at the public boundary.** `SurrogateClaims` and the
   grant carry issuer, audience, subject, `jti`, provider and thumbprint as
   interchangeable byte vectors. An ergonomic facade (validated newtypes;
   untrusted token, verified, admitted and authorized states as types) in
   the application crate, over the unchanged extracted core, so the proofs
   keep their simple types.
2. **Vocabulary.** The code and some proofs say "guest" for the agent's side
   of the proxy (`guest_response`, `GuestReply`); `PROTOCOL.md` fixes the
   terms (agent, broker, proxy, provider). Rename identifiers only where a
   reader gains from it.
3. **Independent review** of the specification, the five guarantees in
   `Garrett.lean` (in particular whether `TransportFaithful` is the right
   native contract and whether the declassification boundary of
   `STATELESS-DISCLOSURE-01` is acceptable), the trusted shells
   (`STATELESS-NATIVE-01`), `STATELESS-CRYPTO-01` (now including nonce
   uniqueness and IND-CPA) and `STATELESS-OPS-01`. An agent cannot
   self-certify it.
4. **Live provider compatibility (maintainer).** One real OAuth provider with
   PKCE and a read-only call, outside tests and CI.
5. **Hardware TPM (maintainer).** The swtpm test against a device TPM, with
   provenance verified by the CA.
6. **Provider-specific read-only catalogues** (narrows `STATELESS-OPS-01`).
7. **An opt-in axiom audit** for this package (the last one, before the
   extraction, found only Lean's standard axioms; see verification.md).
8. **Narrow the native contract further.** A whole-connection two-run
   confidentiality theorem (the per-request one is proved); a syscall-level
   witness that the proxy's only provider writes are `Origin::transmit`
   (today a source guard).
9. **Later, separate increments:** OAuth without the mailbox (a protocol
   change); further acquisition adapters; a multi-replica broker run; the
   release decision.
