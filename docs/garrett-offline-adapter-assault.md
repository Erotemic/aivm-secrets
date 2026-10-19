# Offline HTTP and disclosure boundary hardening (2026-10-19)

**Scope:** standalone Python HTTPS executor; the native Rust manifest HTTPS
response parser; independent native W6 observation oracle; synthetic HTTPS
provider. This increment changes no Rust/Lean authorization controller,
claim format, identity lifecycle, policy language, or external-service
integration. It does **not** establish
W3 complete mediation, W4/W5 whole-service results, W6 I/O refinement, or
real-provider compatibility.

## Why this is worth doing before live-provider tests

A successful *parse* does not show that the provider sent one complete,
well-framed, policy-selected representation. Python's HTTP library can accept
close-delimited JSON, repeated Content-Length, or a response with both
Content-Length and Transfer-Encoding. The baseline executor also accepted 206
Partial Content and JSON/text with the wrong media type. The native Rust
parser already refused these ambiguity cases except for close-delimited
success; that case is now rejected in both implementations. Those differences make a
provider-controlled response capable of producing a successful Python guest
result outside the intended HTTP contract.

The Python adapter now accepts success-body framing only with **one** bounded
Content-Length or **one** supported `Transfer-Encoding: chunked`; it refuses
206, mixed/duplicate framing fields, unsupported transfer codings and
inconsistent parsed lengths. A standards-compliant bodyless `204` is allowed
for text operations (not JSON) without body framing; forbidden 204 framing
is rejected. Non-204 JSON and text results require the corresponding
`application/json` or `text/plain` media type. Non-2xx response
handling, fixed errors, write-outcome uncertainty and positive bounded results
remain unchanged. This deliberately tightens acceptance: a provider that
previously sent a valid JSON body without explicit framing or the declared
media type may now be refused. An operator must review this compatibility
consequence before production use.

The shared synthetic `TLSService` can emit **raw HTTPS response bytes** without
bypassing actual TLS or the production executor. It records requests *before*
returning the custom malformed response. Raw fixtures therefore test parsing
behavior, rather than using stubbed response objects.

## Strengthened native W6 observation contract

`tests/secrets_w6_trace.py` checks an independently declared effect prefix
against the provider-recorded **complete** HTTP header set, rather than a
subset of expected headers. It also checks optional raw header pairs to catch
casefold-duplicate Host/Authorization fields that a dictionary would hide,
HTTP version, typed JSON body equality and duplicate JSON keys, matching
64-character lowercase audit request identities, exact selected public
results when supplied, absence of unapproved metadata, and protected
credential/surrogate exclusion from audit and guest frames.

The expectations for custom headers come from the **host policy** fixture,
not from the received provider headers. Selected public results are explicit
scenario expectations, not computed by invoking the native disclosure
implementation under test. The mutation corpus deliberately changes observed
headers, request bytes, audit records, result fields and surrogate content,
and requires each alteration to be detected by the oracle.

The Rust native manifest parser is hardened to reject close-delimited
non-204 success, and Rust unit tests include the negative case plus positive
bodyless 204. Native integration scenarios exercise ambiguous responses over a real Rust
client/bridge/local HTTPS connection, and a correctly chunked success with a
private discarded field. The working VM has no Rust toolchain, so **those
new Rust-process tests were authored but were not executed here**. Running those new Rust unit and subprocess tests with the pinned
native toolchain remains an acceptance gate; the Rust production change has
not been compiled in this environment.

## Run the offline acceptance gates

All tests use synthetic credentials and loopback TLS providers. They require
no GitHub account, live token, AIVM deployment or hardware TPM. Install the
project in the development environment so the `python -I` child processes use
this source checkout (not another editable install):

```bash
cd ~/code/aivm-secrets
python -m pip install -e '.[tests]'
python -m pytest -q tests/test_secrets_egress.py
python -m pytest -q \
    tests/test_rust_w6_adapter.py::test_w6_reference_trace_oracle_rejects_bypass_and_leaks \
    tests/test_rust_w6_adapter.py::test_w6_reference_oracle_rejects_header_smuggling_and_unselected_release
python dev/verification/w0_contract.py check
python dev/verification/w3_effect_boundary.py check
python dev/verification/w6_adapter.py check
```

With the repository's pinned Rust and Lean toolchains already provisioned,
run the authoritative fail-on-skip synthetic gate (and optionally all tests):

```bash
python dev/verification/system.py --proofs --full-tests
```

This command builds real Rust executables and fails if required native tests
skip; it does not fall back to Python. Dependencies must be cached/provisioned
for genuinely disconnected operation. All Rust W6 scenarios including the new
raw-response tests are included through `WORKFLOW_TESTS`.

## Remaining W3/W6 and information-flow obligations

- An after-the-fact oracle does **not** prove that every Rust/OS/TLS effect is
  reachable only through the reviewed dispatch. W3's dependency, callback,
  drop/unwind and error-path reachability remain open.
- Verified exact outgoing request byte leaves do not establish native route,
  TLS peer, response parse/serialize or all-input guest-frame refinement.
- Timing, connection closure, logs outside the current fixtures, failure
  ordering, semantic leakage within approved fields and secret-dependent
  reflection-denial behavior remain separate observation/declassification
  questions. The W5 theorem's equal-declassification premise is unchanged.
- These tests do not establish crash durability, a trusted VM boundary,
  hardware key custody, a real provider's semantics, or exactly-once writes.

A positive result must include an authorized provider request and precisely
selected reply, as well as the denials. The existing W3/W6 inventory and the
separate W4/W5 proof scopes remain authoritative for those outstanding claims.
