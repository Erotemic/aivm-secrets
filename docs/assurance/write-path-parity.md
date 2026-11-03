# Write path: Python/Rust parity record

**Status (2026-11-02): a record of what each implementation does and which
test or proof shows it, for every write contract.** It is not a proof of
parity for all inputs, and it does not cover live provider semantics. The
write campaign is Phase 5 of the [work queue](../planning/aivm-secrets-active-work.md);
the core contracts are `CORE-08` and `CORE-10` in the
[core API inventory](../planning/aivm-secrets-python-core-api.json).

Python is the reference broker (`aivm_secrets/host/broker.py`,
`aivm_secrets/kernel/machine.py`, `aivm_secrets/host/egress.py`). Rust is
the native bridge (`custody/manifest_session.rs`, `custody/approval.rs`,
the extracted `approval`, `write_gate`, `dispatch` and `provider_exchange`).

## Contracts

| Contract | Python | Rust (tests) | Rust (proofs) |
| --- | --- | --- | --- |
| A write needs both the policy and the host to allow writes | `test_writes_require_both_host_opt_in_and_policy`, `test_writes_require_policy_and_host_mode` | `test_no_provider_call_for_denied_arguments_or_declared_write` | `deny_mode_write_never_runs` (`GarrettWriteGate`) |
| A declared write is a write whatever its HTTP method | `test_a_declared_write_is_gated_like_one_whatever_its_method`, `test_a_declared_write_is_a_write_whatever_its_method` | `test_native_semantic_write_get_needs_approval_and_reads_preserve_it` | |
| In `approve` mode a write waits for one host approval of exactly that request | `test_a_write_waits_for_exactly_one_host_approval`, `test_an_approval_authorizes_exactly_one_exact_write` | `test_native_exact_write_approval_is_bound_and_one_shot`, `test_native_approval_gate_matches_frozen_python_kernel_admission` (frozen kernel vectors) | `admit_write_spec`, `run_admitted_ran`, `approval_preimage_exact` |
| An approval is spent by the attempt, even if the write then fails | `test_an_approval_is_consumed_even_when_the_write_then_fails` | `test_native_failed_approved_write_never_refunds_authority`, `test_native_approval_precedes_preflight_and_is_spent_on_failed_preflight` | `approve_mode_write_ran_consumed_its_approval`, `spent_approval_cannot_be_reused` |
| Two concurrent writes cannot share one approval | (single broker mutex) | `test_native_concurrent_writes_spend_one_approval_once` | `admit_unique`, `install_unique` |
| A write is sent at most once per request | `HTTPSExecutor.execute` called once per ticket | `test_sent_write_failure_is_always_uncertain_without_provider_text` (`len(server.requests) == 1`) | `dispatch_grew`, `calls_match_sends` (`GarrettNativeSendLog`); the driver sends at most once (`provider_exchange`) |
| Any failure after the write is handed to the provider is `outcome_unknown` | `test_any_failure_after_write_dispatch_requires_reconciliation`, `test_a_server_error_leaves_a_write_unknown`, `test_a_write_answered_4xx_may_still_have_been_applied`, `test_a_dropped_connection_after_sending_leaves_a_write_unknown`, `test_post_write_audit_failure_reports_unknown_outcome` | `test_sent_write_failure_is_always_uncertain_without_provider_text`, `test_w6_native_write_wire_and_uncertain_provider_failure` | the driver maps send- and response-stage failures of a write to `OUTCOME_UNKNOWN`; mutant `provider driver lost post-attempt uncertainty` |
| A failure before any byte is sent stays definite | `test_connection_failure_is_definite_even_for_a_write`, `test_a_failed_fact_fetch_before_a_write_is_not_an_unknown_outcome` | | setup- and admission-stage failures keep their own error (`provider_exchange.exchange`) |
| `outcome_unknown` carries no provider text | by construction: `Broker._fail` replaces the error with `outcome_unknown` and keeps only the HTTP status | `test_sent_write_failure_is_always_uncertain_without_provider_text` | `denial_frame_exact` (17 fixed lines) |
| Keyed writes reserve before the send and never replay after uncertainty | `test_write_reservation_is_shared_across_hosts_and_restarts` | `test_uncertain_native_write_is_never_replayed`, `test_concurrent_native_hosts_dispatch_one_write`, `test_python_and_native_brokers_share_global_retry_names` | `keyed_success_reserved_and_finished` |

## Across sessions

Neither implementation retries a write by itself, in one session or across
sessions:

- Within a request the send happens at most once, and its approval is spent
  by the attempt.
- A later request for the same write in the same session is
  `approval_required` again (`spent_approval_cannot_be_reused`).
- A new session starts with no approvals in either implementation (Python
  keeps them in the broker's in-memory kernel state, Rust in
  `custody::approval::Shared`). A write in a new session therefore needs a
  new explicit host approval of the request the operator is shown.
- With a coordinator, a keyed write's reservation is durable and global, so
  a retry under the same name is refused across hosts and restarts.

What neither does without a coordinator is **tell the operator** that an
earlier session's identical write ended `outcome_unknown`. The audit logs
hold the fact: Python writes a `rejected_or_failed` record with code
`outcome_unknown`; the native log has the write's dispatch record (written
before the send) and no `completed` record for it. But `pending` and
`approve` do not consult either log. An operator can approve a repeat without
being reminded to reconcile first.

Closing that is a change to the host approval interface, so it is listed
here for the maintainer to decide rather than made:

1. Which writes count as "the same": the approval digest names the grant,
   which changes per session, so a cross-session match would have to use the
   policy digest, operation and arguments.
2. What the host does on a match: show it in `pending` only, or also require
   an explicit acknowledgement on `approve` (a new field of the host control
   command, in both implementations).
3. Where the record lives: read from the existing audit logs, or a separate
   host-only file of uncertain writes.

The recommended first step is (1) policy digest plus operation plus
arguments, (2) show it in `pending` and require an explicit acknowledgement
to approve, (3) a small host-only file written at the same point as the
`outcome_unknown` audit record. It changes no guest-visible behaviour.
