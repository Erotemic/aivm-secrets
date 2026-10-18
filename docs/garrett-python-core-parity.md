# Normative Python Garrett core versus non-core features

**Contract:** [aivm-secrets-python-core-api.json](planning/aivm-secrets-python-core-api.json).
This is an explicit parity worklist, not a claim that Rust already has parity.
Every current `aivm_secrets/**/*.py` module is classified by the machine-
readable inventory, and the test detects new unclassified files and missing
named core symbols.

## Meaning of core

A **core** Python API specifies *externally observable security behavior* that
must have an independent Rust implementation before declaring full Garrett
parity: admitted/denied actions, scope, binding, epochs, state transitions,
serialization, budget/approval/delegation semantics, permitted destinations,
protected credential handling, declassification, audit ordering, and failure
outcomes. Module classification is a review boundary: it does not require an
identical Rust class hierarchy, Python method names, import paths, process
structure or internal data representation. Even host adapters such as mTLS,
trusted files and HTTPS have core **contracts** despite different
implementations.

A **non-core** module is a convenient interface around core decisions, such
as Python's CLI argument-parser shape, subprocess/test runner interface,
`gh` alias UI, operator help text or package bootstrap. Its effects and errors
still must respect the core contracts. Non-core does not mean untested or safe
to bypass. AIVM-specific provisioning and guest integration are deployment
work, not a requirement to reproduce Python's host package structure in Rust.

## Rust parity map (as of this overlay)

| ID | Required core behavior | Rust status |
| --- | --- | --- |
| CORE-01 | Canonical JSON/wire/denials | Implemented subset; differential gate still required |
| CORE-02 | Binding, enrolled state, epochs, signatures | Implemented subset; differential gate still required |
| CORE-03 | CA, bound certificate/JWT renewal without restart | Native same-key renew/rebind tested; delivery and broader parity open |
| CORE-04 | Authorization, delegation, approval, budgets | Partial |
| CORE-05 | Manifest request/effect and disclosure | Complete native request encoder; finite Python/provider framing tests; broader parity open |
| CORE-06 | OAuth refresh and same-session current-token lease | Native rollover implemented; finite differential coverage, broader parity gate open |
| CORE-07 | Durable cross-host revocation | Native client/server tested; broader parity/refinement open |
| CORE-08 | Globally reserved write keys and no automatic replay | Native dispatch tested against Python and Rust durable servers |
| CORE-09 | Wire key, required-on-write, approved upstream key header | Native manifest subset tested; broader wire/digest parity open |
| CORE-10 | Audits, effect/write ambiguity, guest output | Partial |
| CORE-11 | Trusted paths, TLS authorization and no proxy/redirect | Extracted framing/admission; route, TLS, parser and whole-service correspondence open |

`implemented subset` is *not* whole-contract parity. Rust already has several
independently source-linked Lean proofs for its own models; those do not prove
Python functionality. A newly introduced Python policy field is not accepted
by Rust merely because the field is documented here.

## Gate for promoting a Rust implementation to parity

1. Add a separately implemented Rust entry point for each core contract;
   no Python fallback, Python subprocess, or imported Python policy engine.
2. Version and freeze positive and negative shared vectors for the new core
   wire fields, pure state transitions and denial codes. Match observable
   JSON types, not accidental Python `True == 1` equality.
3. Run independent Python and Rust *native* integration tests over equivalent
   synthetic TLS/HTTP providers and simulated mTLS member clients. Compare
   attempted effects (including zero), trace order, guest disclosure, durable
   restart/revocation behavior, token rollover and ambiguous writes.
4. Audit and, where tractable, refine the Rust I/O adapter to its typed
   controller model. Mark any remaining OS/TLS/fsync assumptions. No theorem
   or Rust build can silently stand in for a missing concrete test.
5. Promote a contract only when its named acceptance conditions pass in both
   backends. Document intentional platform-specific differences separately;
   never hide them by labeling the functionality non-core.

The Python implementation remains independently useful before parity; the
missing Rust features are a specific future implementation queue, not
something this Python overlay claims to have completed.

The [independent primitive runner](primitive-conformance.md) now replays the
six-entry pure value corpus, including binding/digest/frame contracts and stream
framing. This closes the previously pending runner backend. It does not establish
native broker integration or all-input CORE-01 parity; the new adapters remain
runtime-conformance evidence alongside the unchanged freshness proofs.

The [native coordinator increment](verified-coordination.md) tests both live
Python and Rust brokers against one mTLS/SQLite authority. The global retry-key
derivation interoperates. Native request fingerprints now use a normalized
document rebuilt from parsed policy, with [finite differential and durable-record
evidence](verified-policy-normalization.md). Duplicate keys remain refused
regardless of digest. All-input normalization equivalence, The [native authority](native-coordinator-authority.md) now supplies the optional
Rust server with shared protocol/storage vectors and scoped core/history proofs.
SQL/TLS/native I/O correspondence and broader core parity remain open.

The [same-key identity rebinding increment](verified-identity-rebinding.md)
composes native CAS certificate renewal with a host-only rewrap of the identical
opaque broker capability. Both running native profiles and independent Python
JWT opening are tested; the guest file swap remains an operator responsibility.
