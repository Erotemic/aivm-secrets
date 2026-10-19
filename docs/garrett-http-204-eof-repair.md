# Native HTTP 204 end-of-headers repair

**Applies after:** offline HTTP/W6 security, identity-bundle compatibility,
and full-suite fixture/TPM overlays.

The maintainer's October 19 full gate reached `full-python-native`: 2,750
passed, one failed, no skips reported. The only failure was
`tests/test_rust_garrett_manifest.py::test_empty_write_reply_obeys_explicit_response_type[text]`.

The fixture now serves a correctly framed 204 response, but the Rust manifest
parser tried to read one more byte until EOF to detect a body. With TLS,
transport closure may be delayed or may not provide clean `close_notify`.
HTTP 204 ends at the header terminator, so this read can turn a correct reply
into `outcome_unknown` for a write. A cursor unit test returning ordinary EOF
could not reproduce that behavior.

The production parser now considers a header-terminated 204 complete. No
content-length, transfer-encoding, or unframed non-204 success is newly
allowed. The only declared release for text/204 is the empty string; JSON/204
still fails. Stray bytes after the terminator, if any, are not read as an
HTTP representation and cannot appear in the projected guest text. Each
provider operation uses a new connection, so trailing bytes cannot become
part of a subsequent response. This is not a formal proof of HTTP/TLS.

The additional native unit test deliberately returns `WouldBlock` instead of
EOF after the complete headers. The W6 structural checker has a negative
mutation test that reintroduces the unwanted `read_to_end` call. The changed
native module has an updated reviewed-source W3 fingerprint.

## Acceptance on the Rust/Lean development host

```sh
cd ~/code/aivm-secrets
python dev/verification/w3_effect_boundary.py check
python dev/verification/w6_adapter.py check
python -m pytest -q tests/test_secrets_w6_adapter.py
cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib manifest_204_text_does_not_wait_for_transport_eof
AIVM_SECRETS_REQUIRE_TPM_TESTS=1 \
  python dev/verification/system.py --proofs --full-tests
```

The native binary must be rebuilt after applying this overlay. In this
container, no Rust/Lean toolchain is available. The prior maintainer run
establishes other stages passed before this repair; it does **not** establish
a passing full gate after the repair.
