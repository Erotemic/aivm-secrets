# Claim-to-evidence matrix: native read profile

**Status: preparation for NR-5 independent review, not a certification.**
Source boundary: `main` at the commit that last edited this file. Profile:
native Rust `manifest-https-v1`, `writes=deny`, one sequential mTLS guest
session (see [NR-0 profile](../planning/aivm-secrets-native-read-nr0.json)).
An agent assembled this matrix; NR-5 and OUT-5 need a human reviewer to accept
or reject every row. Assumption IDs refer to the
[ledger](../planning/aivm-secrets-assumptions.json) and its
[removal roadmap](../planning/aivm-secrets-assumption-roadmap.md).

Each row names the claim, the checked theorem(s), the external premises it
still needs, the runtime witnesses, and what remains excluded.

## SINK-01: effect confinement

| | |
| --- | --- |
| Claim | Every credential-bearing provider write of a returned request follows current admission, an acknowledged audit record and the send gate, and carries exactly the extracted encoder's output for the captured route. |
| Theorems | `production_accepted_read_has_exact_attempt_accounting_and_guest_frame`, `production_denial_attempts_are_authorized_and_bound` ([GarrettProductionAssurance](../../proofs/GarrettProductionAssurance.lean)); `exchange_send_writes_route_body`, `sent_bytes_are_encoder_output` ([GarrettChannelWork](../../proofs/GarrettChannelWork.lean)); audit chronology in [GarrettProductionAuditRecord](../../proofs/GarrettProductionAuditRecord.lean) |
| Premises | `NATIVE-SINK-01` (no other native credential write), `NATIVE-GLUE-01` (`WrapPreserves`, wiring), `RUST-HTTPS-01`, `RUST-AUDIT-01`, `RUST-CLOCK-01`, `RUST-COMPILER-01` |
| Witnesses | `tests/test_rust_w6_adapter.py`, `tests/test_rust_w6_pending.py`, `tests/test_rust_garrett_dispatch.py`, `tests/test_rust_http_wire.py`, W3/W6 source guards with mutation tests (`tests/test_secrets_w3_effect_boundary.py`, `tests/test_secrets_w6_adapter.py`) |
| Excluded | Delivery to the provider; partial `write_all` effects are attempts, not deliveries; native reachability outside the request primitives |

## TRACE-01: authorized chronology

| | |
| --- | --- |
| Claim | A returned request's receipt trace is sound: admission, audit acknowledgement, late check, provider attempt and completion appear in order; denial, revocation and audit failure stop before a provider attempt. |
| Theorems | [GarrettDispatchTrace](../../proofs/GarrettDispatchTrace.lean), [GarrettOwnedRequestTrace](../../proofs/GarrettOwnedRequestTrace.lean), [GarrettConfinement](../../proofs/GarrettConfinement.lean), [GarrettRequestContext](../../proofs/GarrettRequestContext.lean) (`production_entry_trace`) |
| Premises | `RUST-CLOCK-01`, `EMISSION-RUST-01`, `RUST-COMPILER-01` |
| Witnesses | `tests/test_rust_w6_completion.py`, `tests/test_rust_garrett_dispatch.py`, `native_read_dispatch_audit_to_writer_callback_chronology` (Rust) |
| Excluded | A send already admitted before a later revocation (stated race, `P4-CA-02`) |

## NI-TRACE-01: guest information flow

| | |
| --- | --- |
| Claim | An adaptive guest sees the same histories in two worlds that agree request by request on the selected JSON, the pagination row count and the status class; success frames are the checked encoding of the selected reply and denial frames are one of 17 fixed lines. |
| Theorems | `manifest_release_noninterference` ([GarrettNR4ManifestRelease](../../proofs/GarrettNR4ManifestRelease.lean)); `adaptive_release_same_histories`, `adaptive_exchange_noninterference`, `adaptive_request_noninterference`; `manifest_classes`; `production_read_frame`, `read_confinement_for_every_document`; `denial_frame_exact` ([GarrettPublicError](../../proofs/GarrettPublicError.lean)) |
| Premises | `MODEL-EXCHANGE-01` (transport errors as classes), `RUST-JSON-01` (which documents are compared; not needed for confinement), `NATIVE-GLUE-01` (`Reply::Released` framing) |
| Witnesses | `tests/test_rust_second_provider.py`, `tests/test_rust_garrett_reflection.py`, byte-equality oracles in Rust (`extracted_release_equals_previous_native_release`, `extracted_denial_frames_equal_previous_native_frames`, `extracted_status_equals_previous_native_status`) |
| Excluded | Timing and co-resident side channels; content harm in selected fields; the reflection refusal is an explicit declassification |

## IO-REFINE-01: external boundary

| | |
| --- | --- |
| Claim | Endpoint, request bytes, audit records, status classification, response gate and guest frames are produced by extracted Rust; the remaining native steps are named contracts. |
| Theorems | [GarrettProviderWire](../../proofs/GarrettProviderWire.lean), [GarrettHttpWire](../../proofs/GarrettHttpWire.lean), [GarrettHttpAuth](../../proofs/GarrettHttpAuth.lean), [GarrettLineFrame](../../proofs/GarrettLineFrame.lean), [GarrettProductionResponseGate](../../proofs/GarrettProductionResponseGate.lean), [GarrettChannelWork](../../proofs/GarrettChannelWork.lean) |
| Premises | `RUST-HTTPS-01`, `RUST-MTLS-01`, `RUST-JSON-01`, `RUST-AUDIT-01`, `NATIVE-GLUE-01` |
| Witnesses | `tests/test_rust_http_auth.py`, `tests/test_rust_http_request.py`, `tests/test_rust_http_response.py`, `tests/test_rust_line_framing.py`, NR-2/3 and NR-4 edge guards |
| Excluded | DNS (address is pinned by policy), TLS and OS correctness, power-loss durability |

## Deployment and custody

| | |
| --- | --- |
| Claim | The guest cannot reach host credentials, policy, privileged sockets or other identities in the tested deployment. |
| Theorems | None; this is environment evidence. |
| Premises | `ENV-GUEST-01`, `RUST-PRINCIPAL-01`, `HOST-01`, `LAUNCH-01`, `CHAN-01`, `MEM-01` |
| Witnesses | Maintainer-run real KVM baseline and adversarial extension ([VM acceptance](../aivm-vm-native-acceptance.md)); `tests/test_aivm_vm_acceptance.py`; offline workflow `tests/test_offline_native_guest.py` |
| Excluded | General mount/share reachability, firewall rules, snapshots and clones (`CLONE-01`, `ROLLBACK-01`), vTPM custody (`VTPM-01`), the optional AIVM adapter lifecycle |

## Useful authorized actions (non-vacuity)

| | |
| --- | --- |
| Claim | The system performs useful reads, not only denials. |
| Witnesses | Live GitHub read-only acceptance on real KVM ([OUT-3](../aivm-github-live-readonly-acceptance.md)); `tests/test_rust_second_provider.py` and `tests/test_rust_invoke.py` (synthetic); offline demo `dev/offline_native_guest.py` |
| Excluded | Writes (OUT-4 has its own scope and is not covered by these theorems) |

## How to review a row

1. Open the named theorem and read its statement, not its proof: check that
   no premise restates the conclusion.
2. For each premise ID, read the ledger entry and decide whether the
   contract is acceptable for the deployment you intend.
3. Run the witnesses (`dev/verification/system.py --full-tests` runs the
   synthetic ones) and the focused Lean build of the named modules.
4. Record accept or reject per row; one rejected row blocks the claim it
   supports.
