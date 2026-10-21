# W4/W5/W6: read paths and paired native observations

Status on 2026-10-19: **portable proof-source review and oracle tests pass;
Lean kernel compilation and native subprocess acceptance remain pending on the
maintainer's provisioned machine**. This extends the previously passing
W3/W6 audited dispatch and completed-release changes; it does not change
production Rust or any external service integration.

## Scope and security question

The original W4 request interpreter requires both preflight and final provider
phases. The native manifest executor has three useful read shapes:

| Host-selected path | Provider effects | Public completion |
| --- | --- | --- |
| `noPreflight` | final read | typed selected release after completion audit |
| `checkedOnly` | preflight read; **no final send** | typed checked fact after completion audit |
| `twoPhase` | preflight then final read | typed final release after completion audit |

`proofs/GarrettReadPaths.lean` adds explicit W4 event interpreters for the
first two shapes and reuses the original two-phase interpreter. Its theorem
candidates establish model-level `SoundTrace` and conditional W5 guest
observation equivalence for each shape, using the **extracted Rust**
`manifest.authorize` and recursive `disclosure.project` results through the
existing W4/W5 proofs. Source-level admission and projection are not inferred
from simulated provider calls.

The theorem premises still explicitly declassify admission decisions, provider
and audit outcomes, reflection rejection, selected schema, and public metadata.
Equality of guest requests alone is **not** a confidentiality theorem. In
particular, literal credential reflection can make the public denial status
secret-dependent; differing pagination metadata or frame lengths are likewise
observable. The checked-only model assumes its returned fact is passed through
the selected disclosure schema and completion audit. Its `preflightOK` flag
is supplied by the abstract adapter and **is not** by itself a proof that the
native `manifest.parameter` checked-fact validator accepted the provider bytes.

The new module is **not claimed kernel checked in this overlay**. The optional
`--lean` gate must compile it with the pinned Lean toolchain and audit its
reported axioms. No existing W4/W5 fingerprints, previously checked theorems,
or W4 open-obligation labels were changed. Even after the new module compiles,
W6's universal native-to-Lean simulation obligation remains open.

## Independent paired-run oracle

`tests/secrets_w6_history.py` checks two **real native guest/process**
observations against separate host policy, disclosure, provider-fixture and
normalized-request inputs. It does not use the Rust projection logic, the
Python broker's disclosure routine, or either observed guest result as its
expected release.

A pair is admitted only if the independent host model determines the same
selected result and public pagination metadata in both runs. Each run must
separately have the exact authorized read-effect plan; provider-arrival audit
snapshots; correctly ordered dispatch and completion; normalized request
identity; exact HTTP route, header set and body; fixed public response shape;
and one canonical JSONL guest frame. Both raw guest frames must then be
**byte-identical**. Host audit and guest bytes must not include the explicit
private fixture canaries, file-held credential, or guest surrogate JWT.

The Rust subprocess scenarios are:

1. No-preflight paginated list with a full page, identical selected row IDs,
   different nested/private fields, and stable `possibly_more` metadata.
2. Preflight-only checked fact with identical selected ID and changed
   unselected/private fields, verifying **no final provider send**.
3. Two-phase GitHub-like `pr.diff` with changes confined to the preflight
   provider's discarded fields, and a stable selected diff.

Portable mutants reject changed selected fields, changed pagination metadata
with equal selected value, changed reflection status, private audit fields,
postdated dispatch audit, arbitrary request digest, duplicate guest frame,
extra provider send, and read-to-write plan promotion. These are **finite
falsification tests**, not proof that every possible Rust execution conforms.

## Small acceptance gates

No network access to an external provider, TPM, credential store, or AIVM is
required; the native cases use local TLS and synthetic secrets.

```bash
# Fast: source guards, candidate proof provenance, portable mutation oracles.
python dev/verification/quick_w6_read.py

# Focused Lean compilation of only the new read-path module
# and its W4/W5 dependencies; no Rust rebuild or Charon extraction.
python dev/verification/quick_w6_read.py --lean

# Native-process two-run and causal audit checks using existing fresh binaries;
# no Charon, full pytest suite or Lean. These changes add no Rust source edit.
python dev/verification/quick_w6_read.py --native
```

Run `--native --build` only if the checked binary freshness gate says that the
native executables are missing or stale. To compile just the new Lean module
without rerunning portable oracles, use
`python dev/verification/read_paths.py prove`. A full `--call-linkage` capture
is not necessary for this source-unmodified W4/W5/W6 increment.

## Remaining assurance obligations

- A verified abstraction from **all** native Rust broker and guest effects to
  these `Event`s, including aliases, asynchronous effects, arbitrary failures,
  serializers and complete compiler/dependency reachability.
- Correlation of an abstract audit acknowledgement with real filesystem crash
  durability, and extracted authorization decisions with actual current grant
  snapshots after TLS handshake.
- Complete treatment of connection closure, timing, error pathways, large
  messages, and the credential-reflection denial oracle.
- Writes, coordinator/approvals, OAuth rollover, TPM, administrative flows,
  Python forwarding, hypervisor isolation and real provider interoperability.

The W4/W5 source model is an explicitly conditional **specification**, not a
native kernel proof, a replacement for W3's reachability investigation, or a
claim of whole-service credential secrecy.
