# Claude journal

## 2026-10-22 21:04:30 -0400

Session goal (from the maintainer): get every existing proof working with
Aeneas and remove as many assumptions as possible, keeping the proofs
understandable.

Baseline found: the committed generated Lean was byte-identical to a fresh
pinned extraction, but `lake build` had failed since e7e8071 (three imported
modules were never Lake roots), and `system.py` had failed since 3e4ab7f/48b6c59
on stale review pins, W6 mutation fixtures missing two files, a vacuous
mutation test and an incomplete MANIFEST.in. All repaired; pins refreshed only
after reviewing the drifted source (agent review, not maintainer review).

Removed premises, each with extracted Rust and Lean proof:
- `NativeContext`/`capture`: composed the existing ScopedRequest proof.
- Denial frame: core `public_error` table; 17 fixed JSON lines proved.
- `toJson`/`SelectedConversion`/`toCapturedJson`/`Valid`/`Bound`: moved the
  read release (pagination, projection, assembly, reflection, wire value)
  into core `selected_release::Manifest`; proved noninterference over the
  provider document and the exact success frame.

Finding: the old NR-4 `SelectedConversion` premise silently forced pagination
metadata equal across runs; `possibly_more` reveals the row count. Now an
explicit declassification in `DocumentsAgree`.

Decisions/tradeoffs: kept native `Error::code()` as a host-side `&'static str`
table pinned by test (Aeneas rejects `&'static [u8]` match arms); kept a
test-only copy of each replaced native pipeline as a byte-equality oracle.

Risks: guards are source-shape checks; I tightened one anchor that a mutation
showed was a substring of its bypass. Confidence: high that behaviour is
unchanged (oracle tests + 3210-test gate); the remaining NR-3 sink premise is
the largest open gap.
