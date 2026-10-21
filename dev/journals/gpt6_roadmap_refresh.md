# GPT-6 product-roadmap reconciliation

## 2026-10-21 17:14:36 -0400

Reconciled the planning entry points against source archive `8986ce6` and the
subsequent Track A overlays supplied in this conversation. The formerly long
current active-work preamble was retained as a dated historical snapshot;
`active-work.md` is now a compact status/next-action queue, with a new product
roadmap above the narrow NR read-only assurance roadmap.

Decisions: make useful, explicitly authorized secret use by an untrusted AIVM
guest the finish line. Name the distinct gated deliverables: native conditional
read proof, actual VM isolation, live-provider compatibility, tightly approved
writes, and scoped independent review. Accept the previously recorded NR-0/1
initial baseline at its stated scope. Continue NR-2/3 native primitive/event
correspondence instead of restarting extraction or expanding inventories.

Verification caveat: the latest proof context-fix overlay has no subsequent
successful `GarrettNativeDispatchEvents` build result in the supplied history;
the maintainer did report the corresponding native chronology test passed.
Earlier `e741383` validation is source-specific, not a fresh full-suite run.
Changed Markdown documentation/AGENTS only; security contract JSON, Rust,
proof modules, and runtime behavior were not modified.

Tradeoffs: historical design/extraction text remains accessible but is clearly
labeled rather than rewritten into a misleading current description. Normal
Lean builds stay free of routine axiom dumps; comparative audit belongs at
release review. Next agent should confirm the actual checkout state, run a
focused build on the pending proof, and pursue source-linked native IO/event
composition in parallel with real AIVM VM compartment work.
