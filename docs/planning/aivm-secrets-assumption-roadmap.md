# Assumption removal roadmap

**Purpose.** Every assumption the system relies on is listed in the
[ledger](aivm-secrets-assumptions.json). This roadmap gives each one a class,
a justification and a removal path; the machine-readable rows live in
[`aivm-secrets-assumption-roadmap.json`](aivm-secrets-assumption-roadmap.json),
and `tests/test_assumption_roadmap.py` fails if an assumption is added without
a row. Proof-level premises are ledgered too (`NATIVE-SINK-01`,
`NATIVE-GLUE-01`, `MODEL-EXCHANGE-01`), so the Lean theorems' remaining
hypotheses are on the same list as library and deployment trust.

## Classes and what "removal" means for each

| Class | Meaning | Removal path |
| --- | --- | --- |
| `native-trusted` | Project-owned native Rust the theorems depend on | Move into the Aeneas-extracted core and prove; keep source guards for what cannot move |
| `external-trusted` | Crypto, TLS, OS, std, serde, compiler, Lean kernel | Not removable by extraction: pin versions, narrow interfaces, independent review, final axiom audit |
| `deployment` | Host/VM isolation and operator configuration | Real-VM adversarial evidence (W8/OUT-2) and a deployment guide |
| `specification` | Operator intent and provider semantics | Review; keep policies declarative and small |
| `open-obligation` | Ledgered design gaps (rollback, clone, vTPM, issuer API) | The linked Garrett policy documents |
| `python-reference` | Assumptions only of the Python reference implementation | Retire with the reference, or mirror the native contract |

## Native-trusted entries, in priority order

| ID | Priority | Next step |
| --- | --- | --- |
| `NATIVE-SINK-01` | P1 | Request primitives stop receiving the credential; core-owned opaque credential outside custody/unsealing; independent review of the remaining native call graph |
| `NATIVE-GLUE-01` | P1 | Move remaining native-to-core call sites into extracted wrappers where Aeneas allows |
| `MODEL-EXCHANGE-01` | P2 | Extract transport error classification (status classes already extracted) |
| `EMISSION-RUST-01` | P2 | Extract remaining admission sampling wrappers |
| `APPROVAL-RUST-01` | P2 | Adapter-level single-use linearization in the write (OUT-4) campaign |
| `COORD-RUST-01` | P2 | Extend coordinator proofs to client transport phases |
| `RUST-LEGACY-01` | P2 | Guard legacy socket forwarding out of the native read profile |
| `OAUTH-RUST-01`, `OAUTH-LOGIN-RUST-01` | P3 | Extract remaining state decisions; crypto and sockets stay external |
| `COORD-AUTHORITY-RUST-01`, `COORD-OPERATOR-RUST-01` | P3 | Extract receipt/decision logic; SQL and transport stay external |
| `REBIND-RUST-01`, `BUNDLE-RUST-01` | P3 | Extract remaining consistency decisions; files and crypto stay external |

## Deferred by decision: exact serde parity (`RUST-JSON-01`)

The provider body is parsed by native serde_json. This stays an
`external-trusted` assumption, deliberately not prioritized (maintainer
decision, 2026-10-22):

- read confinement holds for **every** parsed document
  (`read_confinement_for_every_document`), so the parser cannot make the
  broker release credential bytes;
- noninterference is stated over parsed documents and holds for any
  deterministic parse, so the parser only fixes which documents are compared;
- exact parity (the f64 overflow boundary, GraphQL zero test, surrogate rules)
  is costly to reproduce in extracted code for little assurance gain.

An extracted parser remains an optional P3 item if a reviewer needs the
document to be a proved function of the response bytes.
