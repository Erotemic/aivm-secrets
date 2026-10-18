# Decoded JSON credential reflection checks

The native broker's existing recursive reflection check now runs in the extracted
Rust core. `json_reflection::safe` checks every decoded string and object key,
including all nested array/object children. The final canonical-byte reflection
check still runs separately. No provider operation, wire format, policy scope or
identity mode changes in this increment.

## Checked contract

`proofs/GarrettJsonReflection.lean` checks the actual production traversal against
an independent recursive predicate. Admission requires positive recursion fuel,
absence of a literal credential in text and keys, and admission of every child.
The loop contracts cover every element, including the final element. A second
inductive predicate describes a literal occurrence at any tree depth: acceptance
excludes that predicate, and any such occurrence forces refusal. Exhaustion is
refusal and an empty-object witness demonstrates successful admission.

The caller uses fuel 65. The strict JSON parser allows at most 64 container
levels; the extra step covers a terminal scalar. Unit tests construct that exact
boundary and show refusal beyond it. This bound protects recursive traversal; it
is not an agent action quota. The core accepts borrowed data from the existing
`disclosure::Json` type and invokes the previously checked literal byte search.

Only decoded text and object keys are covered. Integer/Boolean representations,
JSON punctuation and matches spanning serialized fragments require the retained
canonical-byte check. The input-to-tree conversion, canonical serializer and
actual call sites remain reviewed/tested adapters. The theorem neither verifies
JSON parsing nor proves complete native mediation or whole-service secrecy.

## Runtime evidence

Independent Python traversal and canonical JSON operations provide a differential
oracle over nested values, keys, nonempty/empty needles, Unicode and explicit
fuel boundaries. Production Python broker comparisons exercise selected public
values containing ordinary credentials and credentials with JSON escapes.
Native provider workflows cover selected text, nested selected objects/arrays,
Unicode-escaped HTTP JSON and credentials in unselected discarded fields.
Discarded fields do not cause a new refusal; the native projection still selects
its reviewed public subset before reflection checks.

A credential containing quotes/backslashes may be absent as literal bytes in the
serialized JSON while remaining recoverable from a decoded string. These tests
therefore exercise both checks rather than treating the final byte search as a
replacement for decoded traversal. The change preserves the existing native
tripwire behavior; it does not claim a newly discovered production bypass.

The check is exact literal matching, not general information-flow control. A
provider can encode or transform a credential, and approved fields can reveal
secret-dependent information without containing its literal bytes. The denial
itself can be an observable oracle. W5's equal approved-declassification and
reflection-status premises remain explicit; this increment does not remove them.

Use focused `lake env lean -DwarningAsError=true GarrettJsonReflection.lean`
from `proofs/` during development. The full Garrett audit and the filtered
`garrett.py mutate --mutation-filter '^json reflection '` family test the checked
contract; they do not certify the remaining adapters or deployment assumptions.
