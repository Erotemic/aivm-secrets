# Concrete provider authentication-header refinement

Both native provider writers use the extracted Rust
`http_auth::append_header` to build their authentication line. It borrows the
credential bytes and appends directly into the caller's zeroizing request
buffer. It does not load credentials, open sockets or create another secret
buffer. The caller still selects the destination and authentication method.

The checked byte contract is:

- An accepted credential contains 1–4,096 bytes, each in ASCII `!` through `~`.
  These bounds preserve the existing native wire contract.
- Invalid credentials return an error without changing any byte of the
  existing buffer. This theorem requires no allocation-capacity premise.
- With enough representable buffer length, successful construction is exactly
  `existing bytes ++ selected prefix ++ credential bytes ++ CRLF`.
  The prefixes are `Authorization: Bearer ` and `X-API-Key: `.
- The existing prefix is preserved byte-for-byte, and the appended segment
  contains exactly one CR and one LF: the final CRLF. Credential bytes cannot
  insert another header, request line or message delimiter into that segment.
- Every actual successful helper return requires the validated credential
  predicate. A positive witness constructs the expected line for both modes.

`proofs/GarrettHttpAuth.lean` proves these properties against the pinned
Aeneas-generated definition of the **actual Rust helper**, not a second Lean
encoder. The accepted total-correctness theorem assumes
`existing length + 22 + credential length + 2 ≤ usize::MAX`; 22 is the longer
prefix. Allocation failure, physical memory erasure and machine-code/compiler
correctness retain the existing standard-model/environment boundaries.

## Native callers and tests

The account writer assembles its complete request in
`account_request_bytes` before connecting. The manifest writer retains its
existing pre-connection encoder, target/custom-header restrictions, body limit
and error ordering. Both append authentication through the extracted helper;
neither independently copies credential bytes into its HTTP header anymore.
Final authority/token admission remains after TLS preparation and immediately
before the existing provider-write continuation.

Rust unit cases check exact account wire bytes for both methods, malformed
credential rejection, unchanged buffers and the 1/4,096-byte helper boundaries.
`tests/test_rust_http_auth.py` runs real native account and manifest processes
with a recording TLS provider, then runs the independent Python HTTP executor.
It compares the actual selected authentication field, destination, method and
target for both modes, punctuation-bearing credentials and 4,096-byte values.
Guest replies and host audit records must omit those synthetic credentials.
These process cases run in ordinary release builds too.

W3/W6 source checks retain the known-call-site review, including refusal of
direct credential appends and assembly after TCP setup. Deliberate bypass edits
update the recorded source hash before testing the structural guard. Eight
re-extracted Rust mutations target the validator, selected prefix, credential
bytes and terminator; they must be rejected by the unchanged proof statements.

```bash
# Focused development: build only the imports, then check this module.
cd proofs
lake build +AivmSecretsGarrettCore +GarrettFoundation
lake env lean -DwarningAsError=true GarrettHttpAuth.lean

# Full recording/acceptance from the repository root.
python dev/verification/garrett.py record
python dev/verification/garrett.py mutate --mutation-filter '^http auth '
python dev/verification/system.py --proofs --full-tests --call-linkage
```

The filtered mutation run covers only the new header obligations; it is not
a new full historical campaign. All runtime credentials are synthetic.

## Remaining boundary

This is a concrete **authentication-line** result. It does not prove that the
entire HTTP request builder has the approved destination/path/body, that the
existing prefix is well formed, that no other native path can emit bytes, or
that TLS delivers to an honest provider. It also does not prove response parser
correctness, guest noninterference, secure memory erasure or VM/TPM isolation.
W3 transitive mediation, the remaining W6 byte adapters and whole native trace
correspondence stay open. The source guard and compiler callback witnesses are
implementation-link evidence with their existing limitations.
