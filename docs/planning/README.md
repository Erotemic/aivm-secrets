# Planning index: aivm-secrets / Garrett

**Start here when joining or resuming.** `aivm-secrets` lets code in a VM
use provider credentials it never holds: the host broker performs named,
policy-approved operations and returns selected fields. It is installed
separately from AIVM and AIVM never requires it. The
[README](../../README.md) lists which properties exist and which are planned.

Read in this order:

1. [Product outcome roadmap](aivm-secrets-product-roadmap.md) — **why the
   project exists, product acceptance gates OUT-0..OUT-5, dependencies,
   isolation/write/release boundaries and anti-drift rules**.
2. [Plan](aivm-secrets-active-work.md): where the project stands and the
   ordered phases of work. This is the only rolling task queue; dated
   histories are records, not tasks. The
   [HTTPS proxy profiles](aivm-secrets-http-proxy-profiles.md) plan (OUT-6,
   HP-0..HP-7) covers the optional proxy frontends.
3. [Native read assurance roadmap](aivm-secrets-native-read-assurance-roadmap.md)
   — NR-0..NR-5 technical read-only scope, actual Rust/Lean seams, assumptions
   and exit criteria. Not a substitute for the product outcome roadmap.
   For the current proof push, use the
   [overnight source-to-observation campaign](aivm-secrets-overnight-formalization.md),
   [copyable agent assignment](../../dev/agent_prompts/overnight-native-read-formalization.md),
   and [maintainer proof tour](../assurance/native-read-proof-tour.md).
4. [W0 conditional-confinement contract](aivm-secrets-conditional-confinement.md)
   and [boundary inventory](aivm-secrets-w0-boundaries.json) — normative
   principals, adversary, allowed releases and scoped sinks.
5. [Assumption ledger](aivm-secrets-assumptions.json) with its
   [removal roadmap](aivm-secrets-assumption-roadmap.md) (class, justification
   and removal path for every entry),
   [formal assurance architecture](aivm-secrets-formal-assurance.md),
   [Garrett proof obligations](aivm-secrets-garrett-verification.md) and
   [modular proof design](aivm-secrets-modular-proof-architecture.md).

For cross-project delivery, also consult the
[standalone operator/guest workflow](../offline-native-operator-guest.md),
[optional AIVM repository/process boundary](aivm-secrets-repository-boundary.md),
[provider-neutral typed integration design](aivm-secrets-agnostic-integrations.md),
[managed-VM integration constraints](aivm-secrets-p4a-managed-vm.md), and
[native write approval design](../native-write-approval.md). These describe
separate implementation and environment obligations; none closes them merely
by being documented.

## Evidence and history

- [NR-0 recorded native baseline](aivm-secrets-native-read-nr0-evidence.md)
  and [machine-readable profile](aivm-secrets-native-read-nr0.json).
- [W3 reachability](aivm-secrets-w3-reachability.json),
  [W4 proof scope](aivm-secrets-w4-proof-scope.json),
  [W5 proof scope](aivm-secrets-w5-proof-scope.json),
  [W6 adapters](aivm-secrets-w6-adapters.json),
  [read-path proofs](aivm-secrets-read-path-proof-scope.json),
  [read-prefix proofs](aivm-secrets-read-prefix-proof-scope.json),
  [read failures](aivm-secrets-read-failure-scope.json), and
  [audited-but-unsent reads](aivm-secrets-read-pending-scope.json).
  A manifest/source fingerprint is not a compiler proof; an extracted theorem
  is not an entire service/I/O refinement; a test witness is not exhaustiveness.
- [October 24](aivm-secrets-active-work-history-2026-10-24.md),
  [October 21](aivm-secrets-active-work-history-2026-10-21.md)
  and [October 19 progress archives](aivm-secrets-active-work-history-2026-10-19.md)
  retain detailed dated validation narratives. They are **historical**, not
  competing roadmaps or instructions to repeat old milestones.

Use `python3 dev/verification/quick_w6_read.py` for portable regression
feedback from the repository root. Run the focused Rust tests when native code
changes and a targeted `lake build <module>` (after `lake exe cache get`) when
Lean changes. Ordinary builds must **not** print bulk theorem or axiom reports;
comparative dependency auditing belongs to an opt-in, final assurance review
per `../../AGENTS.md`. Do not use production credentials or contact real
providers in ordinary CI. The W7 live-provider test is separate and opt-in.

**Documentation upkeep:** update the active queue when real status, blocker,
priority or acceptance changes; update the product roadmap when an outcome
condition/dependency changes; update the NR roadmap when a technical proof
interface or exit criterion changes. Put chronological results in
`dev/validation/` or history, and update proof/sink JSON only with the
corresponding source/proof review. Before calling anything completed, name the
exact checkout, supported profile, positive witness and outstanding premises.
