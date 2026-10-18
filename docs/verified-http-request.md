# Concrete provider request-line refinement

Both native provider builders use `http_request::append_line` from the
extracted Rust core. It validates before appending directly into the caller's
zeroizing buffer. It does not select a socket, load a credential or send bytes.

The checked contract preserves the existing native framing grammar:

- The method is exactly GET, POST or PATCH.
- The target has 1–8,192 bytes, starts with one slash rather than `//`, contains
  only ASCII `!` through `~`, and contains no fragment marker `#`.
- Invalid input returns an error with the original buffer unchanged. Every
  actual successful return requires both predicates, without a capacity premise.
- With enough representable buffer length, output is exactly
  `existing ++ method ++ SP ++ target ++ " HTTP/1.1\r\n"`. No target rewriting,
  decoding, escaping, case folding or method substitution occurs.
- The appended segment has exactly two spaces, one CR and one LF. The caller's
  existing prefix is preserved. A target cannot inject a second request line,
  header or delimiter into this segment.

`proofs/GarrettHttpRequest.lean` checks the actual Aeneas-generated Rust
functions. Both generated copies of the target loop are proved from their
unfolding equations. The accepted-byte theorem assumes
`existing length + method length + 1 + target length + 11 ≤ usize::MAX` in the
pinned standard model. Allocation failure, compiler/extraction correctness and
physical memory erasure retain the existing trust boundaries. The proof uses
standard borrowed-slice equality, iterator and byte-append models; it does not
assume a replacement request encoder. A successful root-target witness prevents
vacuous acceptance.

This grammar prevents framing injection; it is not a complete RFC URI grammar.
Policy compilation remains stricter. For example, the low-level helper copies
`/safe%20literal` unchanged; admitting that string here does not authorize an
operation or claim that every possible provider interprets it identically.

## Native use and validation

The account builder supplies GET and its host-selected path. The manifest
builder supplies the compiled effect's method and target. Both finish building
and validating the request before TCP setup. Final authority/token admission
still occurs after TLS preparation and immediately before the provider write.
Host, Accept, custom headers, body and authentication retain their separate
checks; authentication has its own [byte proof](verified-http-auth.md).

Core units exercise all three methods, literal targets, the 8,192-byte boundary,
malformed and oversized targets, forbidden methods and unchanged-buffer refusal.
`tests/test_rust_http_request.py` compares actual native and independent Python
provider observations for GET/POST/PATCH, two compiled queries and escaped JSON
write bodies. It checks selected disclosure and omission of the synthetic
credential from replies and audit. Existing account/manifest authentication
cases supply further real caller coverage. These process cases also run in
ordinary release builds.

W3/W6 source guards reject known caller bypasses, including after a source hash
is rebaselined. The specialized compiler ledger requires both native builder
paths to the extracted appender and target validator. These graph paths do not
prove dominance or exhaustiveness. Eleven re-extracted Rust mutations exercise
the input predicates, admission guards, target copying and terminator.

```bash
cd proofs
lake build +AivmSecretsGarrettCore +GarrettHttpAuth
lake env lean -DwarningAsError=true GarrettHttpRequest.lean

# From the repository root, with the test environment:
python dev/verification/garrett.py record
python dev/verification/garrett.py mutate --mutation-filter '^http request '
python dev/verification/system.py --proofs --full-tests --call-linkage
```

The filtered campaign covers these new request-line obligations, not the full
historical mutation set. Runtime credentials are synthetic.

## Remaining boundary

This result concerns the appended request line. It does not prove that the
caller chose the authorized method or target, that a preceding buffer is well
formed, or that the complete request has the intended Host, port, headers,
body, Content-Length or destination. It does not prove HTTP response parsing,
TLS/provider behavior, all-output mediation, whole-service noninterference,
VM isolation or TPM key custody. The existing W3/W6 obligations remain open.
