# Status and work queue

The current state of `garrett-stateless` and what comes next, in order. The
dated notes from before the extraction are in [`history/`](history).

## State (2026-11-02)

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
- the connection log records `connected D ok` and `attempted D wire written`;
  every write attempt follows the authenticated connection to the destination of the
  surrogate's provider route (`send_origin`, `protocol_safety`);
- the network-level statement rests on one explicit trusted contract,
  `TransportFaithful`;
- `GarrettConfidentiality`: two-run theorems for the proxy's decision and
  reply and for issuance, with the declassification boundary in
  `STATELESS-DISCLOSURE-01`;
- new adversarial tests (impostor and untrusted-CA destinations over real
  TLS, failed connections and writes, bounded answers, an unrouted provider,
  audit and replies without the credential) and nine new mutants.

**Closing the product boundaries (2026-11-02).**

- **Attempts, emissions and completions are distinct.** The log records
  `attempted D wire written` (the hand-off to the native writer, with its
  report); a `ProviderWrite` is the TLS application data a provider session
  actually carried. `TransportFaithful` now says each session's data is a
  prefix of an attempt's bytes (all of them if the writer reported
  success), and `provider_writes_confined` concludes that every emitted byte
  lies in an authorized request, under partial failure too. A request is
  completed only after a write reported whole (`seg_completed`,
  `CompletedAfterWholeWrite`, `completed_requests_emitted_whole`).
- **A smaller native boundary.** The provider transport is
  `crates/garrett-stateless/src/upstream.rs`: a session exists only after a
  TLS handshake authenticated the core's destination, and its types allow
  one write, with an `Egress` for that destination, after which it can only
  be read. The guard pins it, with new bypass tests.
- **Confidentiality over whole connections.** `connection_declassified`
  (`ConnectionsDeclassified`): two runs of the extracted loop with an
  adaptive agent and credentials that differ send the agent the same bytes,
  up to the first reflection refusal, given network answers that do not
  depend on the credential.
- **Failed issuance without invalid cryptography.** The mailbox's `finish`
  takes an optional `Issuance`; without one the login ends `Uncertain` and
  nothing is sealed. The broker's deliberately invalid sealer is gone.
- **Verification states as types.** `authenticate` returns `Admitted`
  (crate-private field); `unseal` and `decrypt` take nothing else. Outside
  the core neither a forged `Admitted` nor unsealing a `Verified` compiles.
  Operation authorization between them stays proved control flow.
- **Nonces.** `STATELESS-CRYPTO-01` separates single use (Rust), the random
  source (trusted), the probability of a repeat (`GarrettNonce`, at most
  `n(n−1)/2 · 2^−96`) and the rotation limit (the operator's); the guard
  checks every production sealer takes a fresh random nonce.
- **`Garrett.lean`** sorts every result into five layers (extracted
  computations, the effect trace, native network effects under the
  transport contract, cryptography, deployment) and documents each main
  theorem's protected outcome, attacker, source, trust and limit.

## Validation

At the commit that recorded this table (see `git log`):

| Check | Result |
| --- | --- |
| `cargo test` (core and application; also with `--features tpm`) | 63 pass (with two `compile_fail` doctests) |
| `python -m pytest` (including interop, replicas, operations, vectors, purity) | 139 pass |
| `verification/extract.py check` | pass; the model has no `axiom` |
| `lake build` (independent package) | pass (1822 jobs; cold, 354 s) |
| `verification/mutate.py` | all 54 rejected at `d307b86` (3953 s, `--jobs 10`, in the separate-directory copy): `GarrettStatelessProxy` 12, `GarrettStateless` 8, `GarrettStatelessMailbox` 7, `GarrettStatelessComposition` 6, `GarrettStatelessToken` 6, `GarrettStatelessConnection` 4, `GarrettStatelessGrammar` 4, `GarrettStatelessLogin` 4, `GarrettStatelessCodec` 1, `GarrettStatelessState` 1, `GarrettConfidentiality` 1 |
| `verification/shell_guard.py check` | pass (13 checks; 34 bypass tests) |
| Separate-directory check (`verification/standalone.py`) | pass at `d307b86`: a copy of this directory alone, with a fresh virtual environment, Cargo target, toolchain bootstrap and cold Lake build, ran every row above; no source names the origin project outside the allowed history and provenance notes |

## Next, in order

1. **Typed identifiers at the public boundary.** `SurrogateClaims` and the
   grant carry issuer, audience, subject, `jti`, provider and thumbprint as
   interchangeable byte vectors. An ergonomic facade of validated newtypes
   in the application crate, over the unchanged extracted core, so the
   proofs keep their simple types. (The verified/admitted distinction is
   already a core type, `Admitted`.)
2. **Vocabulary.** The code and some proofs say "guest" for the agent's side
   of the proxy (`guest_response`, `GuestReply`); `PROTOCOL.md` fixes the
   terms (agent, broker, proxy, provider). Rename identifiers only where a
   reader gains from it.
3. **Independent review** of the specification, the five guarantees and
   their layers in `Garrett.lean`, in particular: whether `TransportFaithful`
   (prefix of an attempt per provider session) is the right native contract
   and `upstream.rs` meets it; whether `ChannelsAgree` and the
   declassification boundary of `STATELESS-DISCLOSURE-01` are acceptable;
   the trusted shells (`STATELESS-NATIVE-01`); `STATELESS-CRYPTO-01`
   (IND-CPA, the random source, the rotation limit) and `STATELESS-OPS-01`.
   An agent cannot self-certify it.
4. **Live provider compatibility (maintainer).** One real OAuth provider with
   PKCE and a read-only call, outside tests and CI.
5. **Hardware TPM (maintainer).** The swtpm test against a device TPM, with
   provenance verified by the CA.
6. **Provider-specific read-only catalogues** (narrows `STATELESS-OPS-01`).
7. **Narrow the native contract further.** A syscall-level witness that
   the proxy's only provider writes are `upstream.rs`'s (today Rust module
   privacy plus a source guard); the broker's issuance compared over a whole
   login, as the proxy now is over a whole connection.
8. **Later, separate increments:** OAuth without the mailbox (a protocol
   change); further acquisition adapters; a multi-replica broker run; the
   release decision.
