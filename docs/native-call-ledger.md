# Compiler-derived native call-site ledger

`dev/verification/native_calls.py` extracts the default-feature native library
with the pinned Charon driver and builds a structured call-site ledger. This
is an investigation tool for W3/W6, **not a complete call graph, I/O inventory,
mediation gate or additional secrecy theorem**. It changes no broker code.

```bash
python dev/verification/native_calls.py
```

Use `--charon /absolute/path/to/charon` when the prepared tool lives in another
checkout. The matching `charon-driver` must be beside it. Rust's pinned toolchain
and locked dependencies must be available. Each invocation retains its raw
ULLBC, compiler log and `report.json` in a fresh ignored
`.tools/native-calls-*/` directory. Raw extraction is large (about 123 MB for
the initial snapshot); the review ledger is much smaller. No service is started
and no provider credential is used.

The report records Rust input hashes, compiler-driver/tool hashes, source HEAD
and dirty state, raw extraction hash, declaration source coordinates, direct
call targets, call-site source coordinates and unwind destinations. Its IDs
are local to that extraction, not stable identifiers between compiler runs.
It rejects extraction errors, missing owned bodies, unreviewed schema/call/
terminator forms, stale embedded native source and changed Rust inputs or
ledger code during extraction. Charon embeds native source, but omits the
dependency core's source text; the report lists that distinction. Hashing the
current core files is provenance, not an independent source-refinement proof.

All translated functions belonging to the native crate and the referenced
pure core are retained, including private methods and generated functions.
An incomplete traversal starts at native `Bridge::answer`. The traversal
follows only direct calls into those owned bodies. Crucially, functions and
their boundary calls **remain in the ledger even when this traversal misses
them**. A missing path is never evidence that an effect is unreachable.

## Open edges and interpretation

| Recorded class | What remains to establish |
| --- | --- |
| Owned direct call | Actual generic instantiation, control/data flow, admission order and effect semantics |
| Dependency boundary | Dependency behavior, including callbacks invoked by iterators, TLS, serializers and filesystem adapters |
| Unresolved trait/function-pointer call | Which concrete implementations or closures may run, under which arguments |
| Drop count and unwind destinations | Destructor targets, cleanup effects, panic behavior and their observation channels |

Drop counts include compiler-generated cleanup blocks. They are static site
counts, not numbers of runtime effects. The tool does not resolve callbacks,
destructors or external bodies, model concurrency, enumerate actual syscalls,
prove absence of I/O, or distinguish startup authority from guest-request
authority. Binary entry points are excluded from this library extraction.
Do not promote W3/W6 to complete mediation on the strength of this report.

The initial unmodified native library yields 1,908 owned functions and 13,317
call sites, including 68 unresolved trait calls. Only 116 owned functions are
found by the direct traversal from `answer`. In particular, an HTTP executor
passed through a callback must not disappear from review because the direct
traversal stops at that callback. The ledger preserves the other owned bodies
for the follow-up audit. These counts characterize a compiler snapshot; they
are not security scores or acceptance thresholds.

## Validation and next work

`tests/test_native_calls.py` checks that unresolved callbacks and drops stay
explicit, an unvisited callback's dependency sink remains recorded, core
direct calls are traversed, interned call spans resolve, and unexpected or
incomplete extraction is refused. A separate compile-only experiment adds an
unused native helper calling `TcpStream::connect`: the extracted ledger must
retain the helper and its network boundary even though the direct root walk
does not visit it. The helper is never executed and is removed afterward.

The next assurance step is to resolve concrete core-to-native callback edges
with their generic substitutions, then account for dependency callbacks,
destructors and binary startup. Map the resulting candidates to W0 observers
and the W6 byte adapters, with adversarial compiler/runtime checks for omitted
paths. This ledger deliberately supplies no “complete” status that could hide
those obligations. The existing extracted Lean controller proofs and native
workflow evidence retain their separate scopes.
