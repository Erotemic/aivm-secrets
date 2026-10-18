# Coordinated request policy identity

Native coordinated manifest writes now derive their policy digest from the
parsed policy's canonical document, matching Python's `HTTPSpec.to_dict()`
contract for the tested native subset. Previously, Rust hashed the supplied
document directly. Omitted defaults, operation/set ordering and short body-field
syntax could therefore give equivalent accepted policies different identities.

The regression reproduced different stored fingerprints in the real SQLite
coordinator when Python and native Rust each dispatched the same write. Existing
duplicate-key tests did not catch this: the coordinator deliberately refuses a
spent principal/key regardless of the supplied fingerprint. There was no
automatic retry or extra dispatch in that case.

## Implementation and operator inspection

`manifest/normalization.rs` rebuilds operations, parameter sets, checks, default
values, body fields, pagination and GraphQL from the existing parsed types.
It supplies explicit root defaults and canonical command-source environment
names. The native parser still rejects unsupported nonempty CLI tables; this
work adds no command resolver or guest-controlled route/header field.

Normalization and SHA-256 happen once at policy load. The original document
remains available for configuration agreement and the existing native grant's
effective-policy binding. Only the coordinated request fingerprint switches
to the normalized identity. Existing coordinator records are retained; old
principal/key reservations stay spent, even if their old fingerprint differs.
No persisted migration or fallback is performed.

The standalone `manifest-conformance` utility also accepts a policy-only frame:

```json
{"version":1,"policy":{"schema":2,"adapter":"https","service":"tracker","host":"api.example.org","authentication":"bearer","credential_source":{"kind":"file","path":"/host/credential"},"operations":[{"name":"ticket.view","effect":"read","method":"GET","path":"/tickets/{ticket}","parameters":{"ticket":[7]}}]}}
```

Send one JSON object per line to `rust/target/debug/manifest-conformance`.
It returns `ok`, the canonical `policy` and its hexadecimal `digest` without
opening a credential or performing network I/O. The existing frame containing
`request` still compiles its effects. Unknown fields, a supplied null request,
or policy-only `facts` are refused. This is a host development utility, not a
new broker request or administrative endpoint. It works without the Cargo
`conformance` feature, as the existing manifest effect inspector does.

## Evidence and proof scope

`tests/test_rust_policy_normalization.py` independently compares the complete
canonical document and digest with Python, checks normalization idempotence,
permutes equivalent spellings, and changes security-relevant fields to check
that their identities differ. Examples include ranges and finite sets, optional
body fields, checks and capture bindings, return-check operations, page defaults,
GraphQL, text/JSON media defaults, DNS/IP/CA pins, headers, and Unicode source
arguments/literal facts. Invalid policy/frame cases remain negative controls.

The real Python/native coordinator workflow takes turns dispatching on both
backends, checks duplicate denial, and reads the completed records to compare
their request fingerprints. Native input, fully normalized and reordered policy
spellings all participate. Provider observations still check the derived header
and actual credential use. A source-guard negative edit replaces the normalized
policy identity after updating the reviewed fingerprint and must be refused.

This is finite **adapter conformance**, not a new normalization theorem or
all-input Python/Rust equivalence. Existing extracted authorization,
coordination, freshness and disclosure proofs are unchanged. JSON conversion,
canonical serialization, hashing, actual callback placement and TLS/storage
correspondence remain concrete contracts. CORE-05/07/08/09 remain partial;
native coordinator serving, complete native I/O refinement, real multi-host
deployment and provider-specific idempotency semantics remain open.

```bash
python dev/verification/garrett.py record
python dev/verification/system.py --proofs --full-tests
```

These gates use synthetic credentials and explicitly selected native runners.
They must pass without required-test skips before claiming local acceptance.
