# Product roadmap: proof-backed credential use from AIVM agents

**Current product direction — 2026-10-21.** This is the **end-goal and
acceptance-gate** document, not a claim that its gates are satisfied. For the
*ordered next implementation task*, use [active work](aivm-secrets-active-work.md).
For the first formal read campaign, use the
[native read assurance roadmap](aivm-secrets-native-read-assurance-roadmap.md).
The [W0 confinement contract](aivm-secrets-conditional-confinement.md) and
[assumption ledger](aivm-secrets-assumptions.json) remain authoritative for
security definitions; this roadmap does not weaken or silently enlarge them.

## Product outcome and concrete acceptance scenario

An operator provisions a provider credential **only on a trusted host** and
configures an exact, reviewable set of named service operations, destinations,
argument constraints, identity bindings, public result fields, audit rules,
expiry and revocation. An agent inside an untrusted AIVM guest is given a
limited invocation capability, **not the provider credential or access to its
store**. Through an explicitly enabled, versioned process/wire adapter, the
agent can successfully perform *authorized* operations, including an
intentionally limited mutation when that profile is supported. Other
operations, destinations and result fields are refused without an unauthorized
credentialed effect. The host records the actual attempt/completion boundaries
and does not silently retry effects whose outcome may be unknown.

A product acceptance demonstration must include both a useful success and a
denial: e.g. the agent reads selected GitHub pull-request information and,
when a separate narrowly approved write profile is ready, makes one permitted
comment; an unrelated comment, object, destination or operation is denied.
The original credential is absent from guest files, guest responses, guest
logs and guest-reachable host sockets. Revocation blocks *subsequent
admission*, with the final check/send race described accurately.

**This does not mean that an authorized agent is safe to trust with the effects
it has been granted.** The system restricts authority and disclosures, not
agent intent. Provider-supplied approved fields are explicit declassifications;
there is no blanket proof that all response content is harmless. Authorized
provider authentication necessarily reveals credential bytes to the intended
provider connection under the environment/TLS contract, not to the guest.

### Stable architectural rules

- `aivm-secrets` is independently installable and owns credential custody,
  authorization, effect formation, provider dispatch, audit and disclosure.
  Normal AIVM installs, VM operations and SSH/code paths must **not** require
  or automatically activate it. AIVM's adapter is **explicit, optional,
  process/wire-only**; it must not import the trusted broker implementation.
- Host-trusted manifests and fixed service destinations determine the meaning
  of an operation. An agent may choose *permitted typed arguments*, not an
  arbitrary URL, raw authenticated HTTP request, host executable or plugin.
  Extension to other provider protocols needs a separately reviewed executor.
- The normative Python reference and native Rust backend have different
  implemented feature sets. Treat approvals, idempotency, budgets, delegation,
  coordination and error behavior as **explicit parity obligations**; a Python
  test is not evidence that Rust provides that contract.
- Formal claims must concern **production-called, source-linked Rust** and
  precisely defined observations. A Lean proof of a model, a source fingerprint,
  a compiler call-path witness and a synthetic runtime test are distinct kinds
  of evidence. Include external crypto, OS/VM isolation, filesystem, DNS/TLS,
  parser and I/O contracts instead of calling them proved by Lean.
- Do not make TPM, vTPM, external issuer, OAuth, another VM or coordinator
  mandatory for a local broker. Stronger identity/custody profiles require
  independent assumptions and evidence; device presence alone is insufficient.

## Outcome gates and dependencies

| Gate | Deliverable / falsifiable acceptance | Status at this review | Dependencies |
| --- | --- | --- | --- |
| **OUT-0 — Useful offline native vertical slice** | Standalone native operator, authority, broker and guest run with synthetic credential; approved selected read, denied write, audit and revocation; guest package excludes credential | **Demonstrated locally** via [offline workflow](../offline-native-operator-guest.md); same-UID demo is **not** isolation | W1/W2, local fixtures |
| **OUT-1 — Conditional native read assurance** | Scoped `manifest-https-v1`, `writes=deny`, sequential profile; NR-2 execution/event relation, NR-3 actual I/O/sink boundary, NR-4 declassification-aware guest observations and NR-5 independently reviewed claim | **In progress**, not yet an end-to-end service proof. NR-0 and initial NR-1 accepted; NR-2/3 partial; NR-4/5 open | NR-0..NR-5, W0/W3/W4/W5/W6 |
| **OUT-2 — Real AIVM guest integration** | On an actual isolated AIVM VM, explicitly install/enable optional adapter; perform success, denial and revocation using native broker; verify inaccessible host credentials, privileged sockets, policy, other guest identities and prohibited direct egress; normal AIVM is unaffected | **Open**; existing same-UID demonstration does not establish VM compartment | W8; can progress in parallel with OUT-1 |
| **OUT-3 — Live service compatibility** | Opt-in real GitHub read using disposable least-privilege credential; record exact arguments, destination, result projection, provider errors, audit and revocation; no unexpected API effect | **Open**; synthetic GitHub-shaped service is not live compatibility | W7, bounded read profile; can prepare in parallel |
| **OUT-4 — Formally justified authorized mutation** | One narrowly scoped named write succeeds; disallowed effect cannot reach provider; grant/approval/budget/coordination semantics are made explicit; uncertain or partially sent outcomes are never silently retried; exact result and audit observable | **Open for assurance**; existing native/Python write features are not covered by OUT-1's theorem | Extend NR-2/3/4, selected Python/Rust parity, real-provider safety review |
| **OUT-5 — Release-worthy, bounded trust claim** | Versioned host/guest protocol, deployment and recovery instructions, operator workflow, reproducible claim-to-evidence/assumptions matrix, targeted adversarial tests, provenance and independent security review | **Open**; experimental/unaudited until accepted | OUT-1 and relevant OUT-2/3/4 for each advertised profile |

OUT-2 and OUT-3 should **not** wait for all NR-5 proof work. They test
independent premises of the end goal and may expose incorrect integration
assumptions. However, a standalone proof or integration success alone cannot
close OUT-5. The first publishable profile can be narrower than OUT-4 if it is
advertised honestly as *read-only*; it must not imply proved write mediation.

```text
OUT-0 functional offline native witness -- accepted for synthetic, same-UID scope
           |
           +--> OUT-1 NR-2/3 --> NR-4 --> NR-5 read assurance --------+
           |                                                           |
           +--> OUT-2 W8 real AIVM VM/isolation -----------------------+--> OUT-5 reviewed release profile
           |                                                           |
           +--> OUT-3 W7 live read-only provider ----------------------+ 
           |
           +--> OUT-4 narrow authorized write + extended assurance ----+ (when write support is claimed)
```

## Evidence required for a trustworthy claim

At review time, make a **claim-to-evidence matrix**, one row per supported
profile and security property. Each row needs a versioned binary/source
reference, the checked theorem(s) or explicit non-proof evidence, the precise
external premise, native positive/negative witness, and remaining exclusion.
At minimum:

| Property | Evidence to collect | Gap not to waive |
| --- | --- | --- |
| **SINK-01 / effect confinement** | Reachable guest-to-credentialed-sink inventory, production authority checks, actual write-attempt accounting, callback/drop/error paths | Hand-reviewed W3 allowlists and finite call graphs do not establish exhaustive reachability |
| **TRACE-01 / authorized chronology** | Source-extracted admission, durable audit acknowledgment, late check, provider attempt, completion and denial/uncertainty trace simulation | Do not equate requested, attempted, flushed, received or completed effects |
| **NI-TRACE-01 / guest information flow** | Exact selected response fields, fixed error/reflection behavior, metadata, frame bytes/length, close/EOF and adaptive history relation | Do not hide secret-dependent outputs behind an unqualified declassification assumption |
| **IO-REFINE-01 / external boundary** | Source-owned endpoint, byte encoder, writer, audit, parser and frame links plus explicit DNS/TLS/OS/storage/serde contracts | Trusted native callbacks are not themselves proof of correct I/O or guest isolation |
| **Deployment and custody** | Real VM/host checks for guest access to files, sockets, identities, privilege and egress; documented local versus TPM-backed profiles | An offline same-UID test or vTPM presence does not prove isolation/non-exportability |
| **Useful authorized actions** | Positive allowed read, negative disallowed request, revoked request, and (if claimed) one exactly approved write with uncertain-outcome handling | A system that denies everything is not acceptable |

Final proof dependency review is an **opt-in, comparative release audit** only.
Routine Lean work compiles focused modules; don't flood normal builds with
`#print axioms`, `#check` listings or repetitive `sorry`/`admit` scans.
See `../../AGENTS.md` for the development policy.

## Work-selection rules for the next agent

1. Read [active work](aivm-secrets-active-work.md) for the **one next task**;
   the table above is the set of product gates, not six simultaneous requests.
   Verify the actual checkout/dirty state and most recent successful tests;
   do not assume the latest overlay was committed or compiled.
2. Start with the *remaining link* from a production request, not a new
   abstraction or inventory. For Track A, see
   [native dispatch callback observations](../native-dispatch-callback-observation.md),
   [writer simulation](../native-writer-callback-simulation.md), and the
   [NR-2/3 roadmap](aivm-secrets-native-read-assurance-roadmap.md).
3. Preserve the nearest **authorized success** and meaningful denial in every
   vertical slice. Include error, revoked, partial-send and replay outcomes.
4. Do not quietly expand the read-only theorem to native write, arbitrary
   CLI/plugins, shared concurrency, deployed VM secrecy or hardware claims.
   Give those their own scopes, integration tests and proof obligations.
5. On handoff, update only the relevant *current* queue/status row and scope
   contract, not a chronological preamble. Record what passed, what was not
   run, new assumptions, blocker and next acceptance step. Put dated detailed
   results in `dev/validation/`, a focused technical document or history.

### Related sources, not competing priorities

- [Current implementation queue](aivm-secrets-active-work.md) and
  [technical read roadmap](aivm-secrets-native-read-assurance-roadmap.md).
- [Standalone offline workflow](../offline-native-operator-guest.md) and
  [repository/AIVM boundary](aivm-secrets-repository-boundary.md).
- [Provider-neutral typed integration contracts](aivm-secrets-agnostic-integrations.md),
  [optional managed VM design](aivm-secrets-p4a-managed-vm.md), and
  [native write approval design](../native-write-approval.md).
- [W0 security target](aivm-secrets-conditional-confinement.md),
  [assumptions](aivm-secrets-assumptions.json), and
  [formal assurance architecture](aivm-secrets-formal-assurance.md).
