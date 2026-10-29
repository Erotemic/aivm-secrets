# Garrett's July 2026 proposal versus this implementation

**Scope:** the `aivm-secrets` source snapshot used for the October 26, 2026
review, in particular the native `manifest-https-v1` read-only profile.
This comparison is an engineering claim inventory, **not** a security audit,
endorsement by Matthew Garrett, or a new formal proof. Garrett's description
is a design proposal, not a versioned interoperability test suite or an RFC.

Primary proposal: Matthew Garrett, [Securing agentic identity](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/),
July 2, 2026. The original proposal emphasizes a stateless signed surrogate
JWT containing an encrypted provider token, obtained through broker-controlled
browser authentication, then substituted on a certificate-bound mTLS proxy.

## Feature correspondence

| Original proposal feature | Here | Strength of evidence / important difference |
| --- | --- | --- |
| Trusted broker acquires OAuth tokens with browser redirect | Implemented natively, with host-side PKCE, code exchange and encrypted vault; Python reference too | Synthetic HTTPS callback/exchange tests; not an end-to-end live identity-provider guarantee. `GarrettLogin`, `GarrettLoginHistory`, `GarrettOAuth` prove selected extracted transitions under adapter contracts. The offline native demo uses a synthetic static bearer token, **not** OAuth acquisition. |
| Agent gets a signed surrogate instead of a real credential | Implemented: signed Ed25519 JWT, AES-GCM outer envelope, `aivs1` inner capability, bound identity | The versioned **nested** format is a project-specific profile. Exact Rust binding/admission controllers are extracted and proved (`Garrett.lean`, `GarrettBundle`, `GarrettClientMaterial`); signature/decryption primitives are assumed to satisfy their contracts. No general JWS/JWE compliance or arbitrary JWT compatibility claim. |
| Surrogate token carries encrypted credential, permitting stateless brokers/proxies | **Implemented in the separate `garrett-stateless-v1` profile** (2026-10-26, see below); **not** the principal native read workflow | The current `manifest-https-v1` process maintains enrollment/grant, policy, provider credential custody, an audit log and optional OAuth vault. An inner sealed capability may contain credential material in a versioned profile, but current admission and authorization depend on server-side state. No claim that a freshly started broker can run using only the surrogate and encryption keys. |
| mTLS proves the original client possesses the bound certificate's key | Implemented in native client/bridge | Extracted binding checks compare claims against an opaque, authenticated peer identity; real TLS/X.509 chain validation and the signing library remain trusted, tested adapters. A copied **software** key and certificate are an explicit impersonation counterexample. |
| Provider sees the real credential, never the surrogate | Implemented for supported pinned HTTPS operations | Real native provider dispatch, exact request-byte/authorization properties and selective release are tested and partly implementation-linked proved for `manifest-https-v1`. The broker does **not** expose an unrestricted `gh api`, arbitrary URL or arbitrary caller-supplied headers. |
| Instance-bound key in physical TPM or vTPM | Native TPM signing, checked key attributes and synthetic attestation implemented | Isolated swtpm/emulator tests do not establish independent real hardware provenance, secure hypervisor state, clone resistance, signing-oracle isolation or rollback protection. The basic container demo uses a software key only. |
| Safe handling of opaque bearer tokens from ordinary providers | Implemented for supported native pinned providers | Provider auth attaches host-held bearer at egress, selected response fields are released. Endpoint semantics and selected-field disclosure are operator/provider contracts, not an all-provider theorem. |
| Stateless multi-zone distribution without persistent secret storage | **Implemented in `garrett-stateless-v1`** for credential use (any number of independent proxies); the AIVM profile remains stateful by design | The project deliberately adds stateful registry, revocation, approval, audit, OAuth vault and host policy. Multi-host coordinator support is optional, not a demonstration of stateless horizontal scaling. |

## The `garrett-stateless-v1` profile (2026-10-26)

A separate profile now implements the architecture as the article describes
it: [specification](../garrett-stateless-v1.md),
[usage](../garrett-stateless-usage.md) and [proofs](../verified-garrett-stateless.md).
The article uses neither "OAuth" nor "stateless", but it describes both
behaviours: a browser login whose result returns to the broker, and "no
persistent data is ever held in the broker or the proxy". Its section 14
separates what the article requires from the engineering choices added here:

- OAuth code flow with PKCE;
- an AEAD-sealed `state`;
- a transient login mailbox (the article does not say how the result reaches
  the agent);
- a claim-copy policy that defaults to access claims, because provider claims
  can be personal data;
- renewal up to an absolute cap, and key retirement as revocation;
- a reverse proxy whose destination is chosen by the authenticated provider
  claim.

| Article feature | `garrett-stateless-v1` | Evidence |
| --- | --- | --- |
| Agent asks a central broker, authenticated by its certificate | mTLS agent API | Python and Rust, four-way interop |
| Browser login whose redirect returns to the broker | authorization code + PKCE; broker-owned callback; sealed state; confirmation code | synthetic HTTPS IdP; `GarrettStatelessLogin`, `GarrettStatelessMailbox`, `GarrettStatelessState` |
| Wrapper JWT: copied claims, encrypted real token, certificate representation, broker signature | `garrett-stateless-v1+jwt`; `upstream`, `enc`, `cnf`, Ed25519 | shared vectors; `GarrettStateless`, `GarrettStatelessToken` (`verify_token_sound`, `seal_token_ok`) |
| Proxy: mTLS, certificate match, decrypt, swap, forward | stateless mTLS reverse proxy | `GarrettStatelessProxy`, `GarrettStatelessConnection`, `GarrettStatelessProtocol` (`send_origin`) |
| No persistent data; scale by starting instances | the pure `stateless_proxy::decide`; restart and replica tests; an optional strict mode that refuses the OAuth mailbox and the audit file, the only state beyond keys and configuration | `replicas_decide_alike`, `replicas_differ_only_by_answers`, `strict_no_login_state`; tests and demo |
| Opaque provider tokens and API keys | `oauth` or `provisioned` providers; minting needs no OAuth client | spec section 7.1; strict interop tests |
| Proxy decides by the token alone | Garrett's proxy is the default; a read-only proxy (spec section 11.1) narrows a surrogate to listed `GET`/`HEAD` resources, by static configuration (an addition beyond the article) | `composed_egress`, instantiated by `garrett_egress` and `read_only_egress`; `tests/test_garrett_stateless_operations.py`; `STATELESS-OPS-01` |
| JWT and opaque provider tokens | both | tests, vectors |
| Hardware or hypervisor-backed instance key | optional TPM signer (Rust agent) | swtpm test only; no hardware provenance |

This is a project-specific wire profile, not an interoperable standard (the
article specifies no wire format). It is experimental and unaudited.

## Precisely scoped Lean results

- **Extracted implementation-linked Rust decisions.** `Garrett.lean` and
  related modules prove exact issuance/opening and certificate-binding
  preconditions over actual Aeneas-translated Rust *core* controllers. These
  are not separate handwritten algorithms with no implementation linkage.
- **Native read confinement.** For one sequential native mTLS session,
  `manifest-https-v1` and `writes=deny`, the `GarrettProductionAssurance`,
  `GarrettChannelWork`, `GarrettProductionReadFrame`, `GarrettPublicError` and
  related theorems establish authorized/audited/bound provider *attempts*,
  exact encoder bytes, and permitted/denial guest frames, subject to
  `NATIVE-SINK-01` and adapter contracts. The native read proof tour and
  [claim-evidence matrix](claim-evidence-matrix.md) are the authoritative
  boundaries. A send attempt is not a delivery guarantee.
- **Relational information flow.** `GarrettNR4ManifestRelease`,
  `GarrettNR4RequestAdaptive`, `GarrettNR4FrameAdaptive` and supporting
  modules establish indistinguishable guest-frame histories for two modeled
  worlds agreeing on **all declared public observations**: selected JSON,
  pagination row counts, public status/error classes and specific reflection
  outcomes. These are *declassified observations*, not a claim that all
  private source changes are invisible in timings or arbitrary provider data.
- **Symbolic credential secrecy.** `GarrettSecrecy` and `GarrettProfiles`
  prove non-derivability in an ideal-cryptography trace model under explicit
  provider-release and key-custody premises. This is distinct from a
  computational proof for AES-GCM, Ed25519, TLS or real process I/O.
- **The internal `garrett-stateless-v1` protocol.** `GarrettStatelessProtocol`
  composes the extracted mailbox, token codec, key set, admission, renewal and
  proxy connection loop into `protocol_safety`, over every finite execution
  with arbitrary clocks, randomness, peers, OAuth answers and channel
  behaviour. Its only premises are the external boundary of
  `GarrettStatelessBoundary` (AES-GCM correctness for paired keys; no
  Ed25519 forgery in the execution). The native shells' I/O is checked by a
  source guard, not proved ([details](../verified-garrett-stateless.md)).
- **Other scoped transitions.** `GarrettLogin`, `GarrettOAuth`,
  `GarrettServiceHistory`, `GarrettAuthority`, `GarrettTrust`,
  `GarrettEnrollment`, `GarrettWriteGate`, `GarrettApprovalStore` and proxy
  modules prove additional controller and history properties, not one
  monolithic proof of a general OAuth/TPM/write/proxy deployment.

The most recent recorded [axiom audit](axiom-audit.md) (2026-10-24) reports
**1,444 written theorems across 114 modules**, with only Lean's usual three
logical axioms in their transitive dependencies. That is meaningful assurance
about *the stated theorems*, not a percentage of Garrett's proposal, a
computational crypto proof, or a replacement for an independent review.

## Open boundaries before a broad public claim

1. `NATIVE-SINK-01`: establish or independently review that no other native
   path writes provider credential bytes. The sealed credential type, seven
   pinned readers, source guards, mutation tests and a whole-process `strace`
   witness reduce this obligation, but do not kernel-prove it.
2. The assumed TLS, X.509, cryptography, filesystem durability, clock,
   Rust compiler, host/kernel and VM isolation contracts are not Lean-proved.
   JSON body parsing and selected sources of adapter truth remain explicit.
3. Hardware-backed non-exportability with authenticated AK/EK provenance,
   VM cloning and rollback, and authenticated-signing-oracle isolation are
   not established for a general deployment.
4. The stateless architecture is the separate `garrett-stateless-v1` profile
   (above), not the current native read profile. Broad Python/Rust feature parity,
   delegation, native budgets, live OAuth/provider combinations and
   cross-session uncertain writes are separate scopes.
5. Human NR-5 and OUT-5 review and claim acceptance remain outstanding in
   the October 24 active-work plan.

## Reproducible demo

The runnable container demo is described in
[examples/garrett-demo/README.md](../../examples/garrett-demo/README.md):

```bash
bash scripts/garrett-container-demo.sh --pause
```

This uses the **real Rust authority, client and read-only bridge**, a
loopback synthetic HTTPS provider, no network at runtime and an ephemeral
workspace. It does **not** exercise a real OAuth login, production credentials,
VM guest isolation or hardware key custody. Build dependencies require
internet access once. The existing local acceptance test is
`python dev/offline_native_guest.py --walkthrough` with native binaries built.

## Proposed description to the original author

> I implemented the architecture from your "Securing agentic identity" post as
> a separate profile, `garrett-stateless-v1`, in both Python and Rust:
> - a central broker running the browser login (OAuth code flow with PKCE);
> - a broker-signed surrogate JWT that carries the real token encrypted, copies
>   the provider's access claims, and is bound to the agent's client
>   certificate;
> - a stateless mTLS proxy that swaps the real token in.
>
> Independent proxy replicas accept the same surrogate with no shared state,
> and the two implementations interoperate. I proved the Rust decision code in
> Lean, through Aeneas extraction:
> - admission, binding and authentication-before-decryption;
> - login binding;
> - the exact substituted request;
> - no egress on rejection;
> - that the proxy's decision has no adapter-state input.
>
> Crypto, TLS, the provider and the socket shells are stated assumptions.
> Where your post left details open, I made choices and listed them: PKCE, a
> sealed state, a short-lived login mailbox for delivery, an access-only
> default for copied claims (they can be personal data), renewal caps, and key
> retirement for revocation. There's a one-command offline container
> walkthrough if you'd like to look.

Still unsupported: "your protocol is formally verified" (the whole service,
the cryptography and TLS are not), "production-ready", or "interoperable with
other implementations" (there is no common wire standard).
