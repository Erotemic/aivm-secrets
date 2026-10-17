# W5: adaptive modeled-trace information flow

Status: **Lean proof candidate, NOT kernel-verified in the authoring environment**.
W4's source-linked trace model compiles in the maintainer's pinned toolchain,
but W5 needs its own `prove` acceptance run before the following Lean theorems
can be reported as checked. This is a scoped model, not a verified running Rust
service or VM/container isolation claim.

## Question and scope

W5 asks whether changes to protected or unselected provider information can
change what an *adaptive untrusted guest* learns when it communicates with the
broker. The model is the native **two-phase manifest request** from W4; it
imports `GarrettConfinement.lean`, the source-linked Rust
`manifest::authorize`, and the extracted recursive
`disclosure::project`. The native socket/HTTPS/audit/JSON interpreter remains
a W6 refinement obligation.

`GarrettNoninterference.lean` defines:

- `GuestMessage`: a typed denial or schema-selected result. Internal provider
  and audit events are erased by `observeTrace`, but they are not claimed to
  be impossible or unobservable through excluded physical side channels.
- `WireMetadata`: a **separately supplied public observation** with status,
  frame length, pagination (`possiblyMore`) and connection closure. Those
  fields are *not* computed from actual Rust bytes by this model. Concrete
  error codes, bytes and serializers need W6 correspondence.
- `reflectionView`: a modeled post-projection credential-reflection veto.
  The flag can depend on the credential, so **its public denial is an explicit
  declassification condition**, not a proof of full strict noninterference.
- `DeclassificationAgreement`: the exact two-run premises. A preflight and
  final *authorization decision*, all adapter outcome bits, the reflection
  decision, metadata, public schema/fuel/budget and the recursive
  `ProjectionAgreement` must be matched. The last property is deliberately
  weaker than equal raw provider JSON; omitted fields may vary arbitrarily.
- `adaptiveRun`: an arbitrary history-dependent guest strategy and a private
  state transition. `adaptive_noninterference` is conditional on a caller
  supplying an inductive relation preserved by transitions, with the above
  declassification agreement at every reachable pair of states. The actual
  Rust session state and concurrency are not yet shown to satisfy it.

The proof target is, informally:

```text
If paired states are related and every matched request step preserves that
relation and its explicit declassification agreement, then every finite
adaptive guest strategy produces the same modeled observation history.
```

This is **not** obtained by simply assuming equal observed output: the
`disclosure.Proofs.recursive_projection_noninterference` lemma from the
extracted Rust projection derives the selected-output equality from recursive
schema agreement. The public authorization decisions and reflection denial
are *additional release premises*, because their equality does not follow
from schema agreement or from equality of guest requests.

## Why a literal-reflection denial is not hidden

A credential-changing experiment may keep the provider's selected fields
fixed while toggling whether those fields literally contain that credential.
If the broker rejects one execution and returns data in the other, the guest
can distinguish them. The theorem `literal_reflection_is_observable` models
that difference explicitly. The theorem does **not** prove the denial flag is
secret-independent. A blanket claim of strict credential noninterference
would be false without a different release policy or implementation strategy.

The native test `tests/test_rust_w5_noninterference.py` exercises this using a
synthetic provider and Rust binaries: it mutates an ignored field (including a
literal credential), a selected title, and a selected title containing the
credential. Expected results are respectively an identical reply, an approved
changed reply, and a credential-free rejection. This test checks behavior but
cannot discharge the W6 trace-correspondence obligation. It is skipped when
Rust binaries are unavailable.

## W5 theorem families

| Family | What it actually establishes |
| --- | --- |
| `observe_after_preflight`, `observe_after_final`, `observe_case_normal_form` | Model reduction from W4 two-phase events to the guest-facing response branch, including denial paths |
| `observe_disclose_congr`, `observe_disclose_noninterference`, `ignored_provider_field_noninterference` | Two provider JSON values with equal source-level projections have equal modeled guest disclosures; recursive agreement permits different discarded fields |
| `request_noninterference` | Equal explicitly declassified decisions/metadata plus projection agreement give equal single-request modeled observations |
| `adaptive_noninterference` | Finite history-dependent strategies yield identical observation histories under a private-state bisimulation-style step premise |
| `denied_request_witness`, `allowed_request_witness`, `boolean_projection_witness` | Nonempty allowed/denied behavior in the model, with the Boolean projection witness linked to a checked Rust projection |
| `literal_reflection_is_observable`, `metadata_difference_is_observable` | Counterexamples to treating changed denial or metadata as invisible |

## Exclusions and follow-on work

W5 does **not** prove the premise that two different credentials receive equal
authorization decisions, audit/provider results or reflection flags. Such
differences may be legitimate declassifications, security bugs, or oracles,
depending on the policy. The exact classification is a policy/assurance review
question. It also does not prove that wire metadata is public-independent or
that the real Rust server has no alternative guest-visible output path.

Timing, power/cache/microarchitectural observations, unmodeled observers,
actual ciphertext, other backends, and arbitrary host filesystem/network
access remain out of scope. Native profiles without preflight, checked-fact
composition, OAuth refresh, administration, legacy Python forwarding and
concurrent state transitions require additional work in W6 or separate proofs.

## Compile during development

From `~/code/aivm-secrets`, with the pinned Lean/Aeneas backend installed:

```bash
python dev/verification/w5_noninterference.py prove
```

`prove` builds **only W4's imported Lean proof modules**, compiles W4 into
its importable `.olean`, then compiles W5.
It suppresses successful dependency output and prints Lean diagnostics when
compilation fails. There is no per-theorem axiom report. The ordinary compile
command intentionally does **not** compare source hashes, so proof edits can be
checked immediately. Lean rejects unresolved goals and syntax/type errors.

Use `python dev/verification/w5_noninterference.py check` separately when
reviewing the W5 source/assumption inventory and proof fingerprints; it is
not part of the normal compilation loop. The W0/W3/W4 checkers and the Python
regression tests remain separate gates, rather than being run every time a
Lean lemma changes. A passing W5 compile still does not establish W6's
runtime I/O correspondence.

Opt-in native mutation integration (requires Rust binaries from W2):

```bash
cargo +nightly-2026-09-17 build --manifest-path rust/Cargo.toml --bins
AIVM_SECRETS_RUST_AUTHORITY_ADMIN="$PWD/rust/target/debug/garrett-authority" \
AIVM_SECRETS_RUST_GARRETT_BRIDGE="$PWD/rust/target/debug/garrett-bridge" \
AIVM_SECRETS_RUST_GARRETT_CLIENT="$PWD/rust/target/debug/garrett-client" \
python -m pytest -q -ra tests/test_rust_w5_noninterference.py
```

Only publish a **model-level** W5 theorem after the kernel gate succeeds;
service-level confidentiality remains conditional on the W6 I/O and
state-transition correspondence plus the environmental isolation contracts.
