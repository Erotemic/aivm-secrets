# Planning index: aivm-secrets / Garrett

- [NR-0 native read evidence freeze](aivm-secrets-native-read-nr0-evidence.md) — pinned source/sink/fixture scope, fast reproducible acceptance, and NR-1 extraction handoff.

For a new contributor or coding agent, read these in order:

1. [Current priority and acceptance queue](aivm-secrets-active-work.md).
   **Only this file ranks current work.** It names the next NR-0 through NR-5
   native read-assurance tasks and a parallel offline guest-utility checkpoint.
2. [Detailed native read assurance roadmap](aivm-secrets-native-read-assurance-roadmap.md).
   Task owners, Rust/Lean links, dependencies, trust boundaries, evidence types,
   exit criteria, acceptance commands and cross-agent handoffs.
3. [W0 conditional-confinement contract](aivm-secrets-conditional-confinement.md)
   and [boundary inventory](aivm-secrets-w0-boundaries.json).
   Normative security scope, sinks, adversary and allowed releases.
4. [Formal assurance architecture](aivm-secrets-formal-assurance.md),
   [Garrett-specific proof obligations](aivm-secrets-garrett-verification.md),
   [assumption ledger](aivm-secrets-assumptions.json) and
   [modular proof architecture](aivm-secrets-modular-proof-architecture.md).
5. Machine-readable scoped evidence records:
   [W3 reachability](aivm-secrets-w3-reachability.json),
   [W4 proof scope](aivm-secrets-w4-proof-scope.json),
   [W5 proof scope](aivm-secrets-w5-proof-scope.json),
   [W6 adapters](aivm-secrets-w6-adapters.json),
   [read-path proofs](aivm-secrets-read-path-proof-scope.json),
   [read-prefix proofs](aivm-secrets-read-prefix-proof-scope.json),
   [read failures](aivm-secrets-read-failure-scope.json) and
   [audited-but-unsent reads](aivm-secrets-read-pending-scope.json).
   Each has its own validation semantics: a source guard is not a Lean theorem;
   a finite native witness is not a universal I/O simulation.

The [October 19 historical active-work archive](aivm-secrets-active-work-history-2026-10-19.md)
retains earlier dated milestones and detailed implementation notes, including
superseded pass counts and pending statuses. It is historical reference, **not**
a parallel current implementation plan. Other `aivm-secrets-*.md` documents
in this folder remain specifications, specialized designs or deferred work,
not competing active task queues.

For ordinary local iterations, use
`python dev/verification/quick_w6_read.py`; add `--native` for the selected
actual Rust tests and `python dev/verification/read_prefixes.py prove` for the
Lean kernel/axiom audit. Reserve full suite and specialized compiler
extraction for relevant changes and scheduled integration checkpoints. Do not
use real services or production credentials for ordinary tests.

**Documentation hygiene:** update the active queue when a task's evidence or
priority changes; update the detailed roadmap if interfaces/dependencies or
exit gates change; update proof/assumption scope JSON only with its required
source/proof review. Record actual tool output and remaining obligations before
claiming completion. Never label the complete native read claim as proved from
a passing quick gate alone.
