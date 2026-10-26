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
| Surrogate token carries encrypted credential, permitting stateless brokers/proxies | **Not equivalent in the principal native read workflow** | The current `manifest-https-v1` process maintains enrollment/grant, policy, provider credential custody, an audit log and optional OAuth vault. An inner sealed capability may contain credential material in a versioned profile, but current admission and authorization depend on server-side state. No claim that a freshly started broker can run using only the surrogate and encryption keys. |
| mTLS proves the original client possesses the bound certificate's key | Implemented in native client/bridge | Extracted binding checks compare claims against an opaque, authenticated peer identity; real TLS/X.509 chain validation and the signing library remain trusted, tested adapters. A copied **software** key and certificate are an explicit impersonation counterexample. |
| Provider sees the real credential, never the surrogate | Implemented for supported pinned HTTPS operations | Real native provider dispatch, exact request-byte/authorization properties and selective release are tested and partly implementation-linked proved for `manifest-https-v1`. The broker does **not** expose an unrestricted `gh api`, arbitrary URL or arbitrary caller-supplied headers. |
| Instance-bound key in physical TPM or vTPM | Native TPM signing, checked key attributes and synthetic attestation implemented | Isolated swtpm/emulator tests do not establish independent real hardware provenance, secure hypervisor state, clone resistance, signing-oracle isolation or rollback protection. The basic container demo uses a software key only. |
| Safe handling of opaque bearer tokens from ordinary providers | Implemented for supported native pinned providers | Provider auth attaches host-held bearer at egress, selected response fields are released. Endpoint semantics and selected-field disclosure are operator/provider contracts, not an all-provider theorem. |
| Stateless multi-zone distribution without persistent secret storage | **Not implemented as specified** | The project deliberately adds stateful registry, revocation, approval, audit, OAuth vault and host policy. Multi-host coordinator support is optional, not a demonstration of stateless horizontal scaling. |

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
4. The original stateless architecture and unrestricted proxy translation
   are not the current native read profile. Broad Python/Rust feature parity,
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

> I implemented a working Rust/Python credential-brokering system inspired by
> your agent identity proposal: signed, encrypted, certificate-bound surrogate
> capabilities, mTLS, host-held provider credentials, OAuth acquisition and
> pinned-provider dispatch. I've also proved a substantial subset of the
> extracted Rust authorization, binding, emission and disclosure logic in Lean.
> It's not a byte-for-byte implementation of your proposed stateless proxy,
> and the security claims are scoped to explicit configurations and trusted
> boundaries. There's a fully synthetic, runnable native walkthrough if you'd
> be interested in reviewing the design and its proof assumptions.

A stronger phrasing such as "your *full* protocol is implemented and formally
verified" is not supported by the above matrix.
