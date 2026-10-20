# Main reconciliation, October 20, 2026

The maintainer's 21 commits from `7120838` through `f15b852` contain all
previously accepted local work. Main was fast-forwarded without rewriting
those commits. The current product-first queue and native read assurance
roadmap remain authoritative.

The unfinished local response-admission experiment is preserved in commit
`cc69a4d` on `codex/response-admission-wip-20261020`. Its larger core scanner,
3,820-row corpus and unfinished `GarrettHttpResponse.lean` proof are **not**
accepted main work. In particular, its old EOF/204 behavior must not replace
the maintainer's newer explicit-framing and header-terminated 204 repair.

All older worktrees were also clean. The abstract resource-lease experiment
remains at `10800c5` on `garrett-review-checkpoint`; it is deferred under the
current implementation-linked priorities. Earlier dispatch source work is
already carried by main's `323a3e2`; its old fork and review journals remain
preserved, without merging duplicate code or historical acceptance notes.

The consolidation takes only its reproduced runtime repairs and 30 process
and reference tests: both native response parsers require exactly three ASCII
status digits, the reason-phrase separator, valid reason bytes, and ASCII
SP/HTAB header whitespace. Successful length, leading-zero length and chunked
responses retain Python-reference effect and selected-result behavior.
These tests do not prove complete HTTP parser correspondence.

Additional integration repairs:

- Format the incoming Rust and retain the source guards' transition/uncertain
  write checks across normal Rust formatting; bypass mutants still must fail.
- Re-extract the actual `read_transition::prepare` and `acknowledge` source.
  Their presence in generated Lean is not the pending NR-1 simulation proof.
- Repair the read-prefix list proof using the existing per-step theorem and
  `List.map_congr_left`, avoiding the observed kernel recursion failure.
- Include the new read proofs and offline operator executable in the source
  distribution, and require the native pending/read-profile checks, focused
  read-prefix kernel gate and offline product witness in `system.py`.
- Refresh source/proof coordinates without promoting their assurance scope.

The acceptance record is `dev/validation/2026-10-20-main-reconciliation.json`.
It records actual commands and results for the consolidated source commit;
earlier acceptance reports do not certify this newer implementation.

SSH authentication was rejected on this host. Public HTTPS fetch confirmed
`origin/main` without changing the configured SSH remote. No push was made.
The AIVM checkout remains on `dev/0.6.2`; its vTPM commit `24c5fe0` is already
on that remote branch. AIVM's separate release `main` was not merged here.

This remains experimental and unaudited. Native read-to-trace simulation,
transitive I/O mediation, deployed guest isolation and broader parity remain
open; no whole-service confidentiality claim follows from these checks.
