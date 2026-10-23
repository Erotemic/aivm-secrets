# Claim-to-evidence matrix: HTTPS proxy, credential-substitution profile

**Status: preparation for independent review, not a certification.** Profile:
`credential-substitution` (Python `aivm-secrets proxy` and native
`garrett-proxy`), as defined in the
[plan](../planning/aivm-secrets-http-proxy-profiles.md). An agent assembled this
matrix, so a human reviewer must accept or reject each row. Assumption IDs refer
to the [ledger](../planning/aivm-secrets-assumptions.json).

**This profile makes no authority-confinement claim.** The guest can do
whatever the credential can do at a configured origin, except what the deny
list names (`PROXY-AUTHORITY-01`). Use it only for narrowly scoped
credentials.

## PX-1: where the credential goes upstream

| | |
| --- | --- |
| Claim | The credential is written upstream only as one authentication line, after every guest field, on a request for a configured origin. No guest field named `Authorization`, `X-Api-Key`, `Proxy-Authorization`, `Cookie`, a method-override field, `Range` or `If-Range` (19 names, any ASCII case) is forwarded. A guest cannot add a header line. |
| Theorems | `encode_upstream_contract`, `forwarded_drops`, `dropped_eq`, `clean_field_single_line` ([GarrettProxyHttp](../../proofs/GarrettProxyHttp.lean)); `accepted_header_exact` ([GarrettHttpAuth](../../proofs/GarrettHttpAuth.lean)) |
| Premises | `PROXY-NATIVE-01` (the native shell writes only the encoder's buffer upstream), `PROXY-TLS-01`, `PROXY-PARSE-01` (provider routing semantics), `RUST-COMPILER-01` |
| Witnesses | `tests/test_proxy_substitution.py`, `tests/test_rust_proxy.py` (native, stock curl), byte parity `tests/secrets_vectors/proxy-http-v1.tsv` checked by Python and Rust |
| Excluded | Delivery; the provider's interpretation of paths for the deny list |

## PX-2: what the guest receives

| | |
| --- | --- |
| Claim | A response released to the guest never contains the credential's exact bytes. Listed percent, hex, base64 and JSON-`\/` forms are also refused, and case-sensitive forms are also searched with line breaks removed (MIME-wrapped base64). Every refusal is one of eleven fixed responses that name only a code. |
| Theorems | `guest_response_contract`, `reflects_spec`, `unwrapped_spec`, `reflection_forms_include_raw`, `refusal_exact` ([GarrettProxyResponse](../../proofs/GarrettProxyResponse.lean)) |
| Premises | `PROXY-REFLECT-01` (other encodings and freshly minted credentials are not detected), `PROXY-NATIVE-01` |
| Witnesses | Reflection, compression and redirect tests in both suites; response and refusal parity vectors |
| Excluded | Credential amplification (`PROXY-AUTHORITY-01`), timing |

## PX-3: who can use the session, and for how long

| | |
| --- | --- |
| Claim | Only a client presenting the session token can open a tunnel, and only to a configured origin on port 443. Revocation and expiry are re-checked before every upstream request, including inside an open keep-alive tunnel. The session ends when the parent's stdin closes. |
| Theorems | None: tested behaviour of the Python reference and the native shell. |
| Premises | `PROXY-NATIVE-01`, host process isolation (`HOST-01`) |
| Witnesses | Tunnel-auth, revocation-in-tunnel, expiry and lease-end tests in `tests/test_proxy_substitution.py` and `tests/test_rust_proxy.py` |
| Excluded | A guest that already holds the token can use it until the session ends |

## PX-4: deployment

| | |
| --- | --- |
| Claim | The guest receives a CA, a CA bundle and an env file, never the credential. With AIVM's opt-in `firewall.public_egress = false`, the guest has no direct public egress, and the proxy keeps working over the host-initiated SSH session. |
| Theorems | None: environment evidence. |
| Premises | `PROXY-EGRESS-01` (default AIVM egress is open; the opt-in mode is untested on a real VM), `ENV-GUEST-01`, `PROXY-TLS-01` |
| Witnesses | `tests/test_proxy_session.py` (local guest, Python and native proxy); AIVM `tests/test_secrets_native.py`, `tests/test_firewall.py` |
| Excluded | Real-VM runs of `proxy-session` and of the egress mode (maintainer actions) |

## How to review a row

1. Read each theorem's statement, not its proof, and check that no premise
   restates the conclusion.
2. Decide whether each premise is acceptable for the deployment you intend.
3. Run the witnesses: `dev/verification/system.py --full-tests` runs them
   with the native binaries, and `lake build GarrettProxyHttp
   GarrettProxyResponse` checks the proofs.
4. Record accept or reject per row. PX-1 and PX-2 are the claims this profile
   adds over a plain proxy; nothing in this matrix supports least privilege.
