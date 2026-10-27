# Axiom audit

The routine proof check is compilation. This audit is the separate,
end-of-formalization check that [AGENTS.md](../../AGENTS.md) describes: for every theorem
written in the proof modules, which axioms does it depend on, transitively?
It runs only on request:

```bash
python dev/verification/axiom_audit.py run        # differences from the baseline
python dev/verification/axiom_audit.py baseline   # record a reviewed baseline
```

`run` prints only what differs from [axiom-baseline.json](axiom-baseline.json):
- theorems that depend on anything outside the allowed set;
- added or removed theorems;
- theorems whose axiom set changed.

The allowed set is Lean's three standard axioms (`propext`,
`Classical.choice`, `Quot.sound`) plus the named axioms Aeneas emits for
opaque Rust items in the extracted model.

## Result, 2026-10-26 (garrett-stateless-v1 internal protocol)

- 1,885 written theorems in 128 root modules; 388 added by the
  campaign that composed `protocol_safety` (the mailbox, codec, grammar,
  token, login-state, round-trip, connection, protocol and witness modules).
- `outside_allowed` and `model_axiom_use` are both empty: every theorem,
  including `protocol_safety`, depends only on `propext`, `Classical.choice`
  and `Quot.sound`. The boundary propositions of
  `GarrettStatelessBoundary` are premises, not axioms.
- One theorem was removed: `login_surrogate_bound_to_starting_peer`, whose
  `StageOnly` premise the mailbox extraction made unnecessary. No theorem
  changed its axiom set. The baseline was re-recorded after this run.

## Earlier result, 2026-10-26 (garrett-stateless-v1)

- 1,497 written theorems in 117 modules. The 53 additions are the three
  `GarrettStateless*` modules (48 theorems, plus the step-attribute
  auxiliaries Lean generates for them).
- `outside_allowed` and `model_axiom_use` are both empty: every theorem still
  depends only on `propext`, `Classical.choice` and `Quot.sound`.
- No theorem was removed or changed its axiom set. The baseline was
  re-recorded after this run.

## Result, 2026-10-24

- 1,444 written theorems in 114 modules (rerun after the history models; first run: 1,412 in 112). Lean-generated equation, size and
  injectivity lemmas are left out.
- Every theorem depends only on `propext`, `Classical.choice` and
  `Quot.sound`.
- No theorem depends on `sorryAx`, and none on the two axioms in the
  extracted model (`MaybeUninit`, `Result.is_err`).

The first run found one exception, which is now fixed. `xor_zero`, in the
constant-time comparison behind proxy authentication, was proved with
`bv_decide`. That tactic adds an axiom which trusts Lean's native code
evaluator. Three theorems inherited it: `same_secret_loop_ok`,
`same_secret_true` and `authenticated_true`. `xor_zero` and its neighbour
`or_zero` now have bit-by-bit kernel proofs. No proof uses `bv_decide` or
`native_decide` any more.

## What this does and does not show

The audit shows that the theorems rest on Lean's logic and nothing else
written in Lean. It does not check that the theorem statements say what the
proof tour claims. That is the human part of the NR-5 review. It also does
not cover what the proofs take as premises; those are listed in the
[assumption ledger](../planning/aivm-secrets-assumptions.json).
