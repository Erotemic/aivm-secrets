#!/usr/bin/env python3
"""Reproduce the Rust Garrett port, extracted contracts, symbolic secrecy and parity.

Run bootstrap once, then check and mutate with the project's test Python.
No provider credentials, host authority state or hardware keys are read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import freshness as base

ROOT = base.ROOT
PROOFS = base.PROOFS
MANIFEST = PROOFS / "garrett-manifest.json"
PROFILES = [
    "nested-bridge-v1",
    "account-status-v1",
    "p256-client-enrollment-v1",
    "native-authority-v2",
    "native-oauth-vault-v2",
    "native-pkce-login-v1",
    "manifest-https-v1",
    "native-coordination-client-v1",
    "native-same-key-rebinding-v1",
    "native-coordinator-authority-v1",
]
THEOREMS = [
    "aivm_secrets_garrett_core.Proofs.bytes_ne_spec",
    "aivm_secrets_garrett_core.Proofs.issue_contract",
    "aivm_secrets_garrett_core.Proofs.present_contract",
    "aivm_secrets_garrett_core.Proofs.returned_of_spec",
    "aivm_secrets_garrett_core.Proofs.present_exact",
    "aivm_secrets_garrett_core.Proofs.present_accepted_iff",
    "aivm_secrets_garrett_core.Proofs.stolen_surrogate_wrong_peer",
    "aivm_secrets_garrett_core.Proofs.stolen_surrogate_cannot_be_used",
    "aivm_secrets_garrett_core.Proofs.issuance_cannot_outlive_enrollment",
    "aivm_secrets_garrett_core.Proofs.authorized_use_positive_witness",
    "aivm_secrets_garrett_core.Proofs.open_surrogate_contract",
    "aivm_secrets_garrett_core.Proofs.open_rejects_unbound_before_unsealing",
    "aivm_secrets_garrett_core.Proofs.open_stolen_surrogate_rejected",
    "aivm_secrets_garrett_core.Proofs.open_successful_use",
    "aivm_secrets_garrett_core.Proofs.prepare_issue_contract",
    "aivm_secrets_garrett_core.Proofs.issue_surrogate_contract",
    "aivm_secrets_garrett_core.Proofs.inactive_enrollment_never_sealed",
    "Garrett.Protocol.derivation_preserves_confinement",
    "Garrett.Protocol.provider_credential_not_derivable",
    "Garrett.Protocol.private_key_not_derivable",
    "Garrett.Protocol.surrogate_can_be_public",
    "Garrett.Protocol.every_trace_observation_safe",
    "Garrett.Protocol.all_traces_preserve_credential_secrecy",
]
THEOREMS += [
    "aivm_secrets_garrett_core.credential_use.Proofs.require_use_current_contract",
    "aivm_secrets_garrett_core.credential_use.Proofs.authorize_use_contract",
    "aivm_secrets_garrett_core.credential_use.Proofs.release_reply_exact",
    "aivm_secrets_garrett_core.credential_use.Proofs.release_noninterference",
    "aivm_secrets_garrett_core.credential_use.Proofs.authorize_use_exact",
    "aivm_secrets_garrett_core.credential_use.Proofs.credential_use_contract",
    "aivm_secrets_garrett_core.credential_use.Proofs.inactive_grant_never_executes",
    "aivm_secrets_garrett_core.credential_use.Proofs.unauthorized_operation_never_executes",
    "aivm_secrets_garrett_core.credential_use.Proofs.credential_use_successful",
    "aivm_secrets_garrett_core.credential_use.Proofs.credential_use_noninterference",
]

THEOREMS += [
    "aivm_secrets_garrett_core.protocol.Proofs.prepared_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.finish_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_outer_failure",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_stolen_surrogate",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_inner_failure",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_unauthorized_operation",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_after_prepared",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_observer_failure",
    "aivm_secrets_garrett_core.protocol.Proofs.prepare_successful",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_successful",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_projection_noninterference",
]

THEOREMS += [
    "aivm_secrets_garrett_core.protocol.Proofs.recorded_issuance_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.recorded_issuance_failure",
    "aivm_secrets_garrett_core.protocol.Proofs.recorded_issuance_success",
    "Garrett.ControllerHistory.all_histories_correspond",
    "Garrett.ControllerHistory.dispatch_continuation",
    "Garrett.History.signature_origin_monotone",
    "Garrett.History.deduction_preserves_signature_origin",
    "Garrett.History.trace_is_public",
    "Garrett.History.every_observation_has_signature_origin",
    "Garrett.History.protected_signature_was_issued",
]

THEOREMS += [
    "aivm_secrets_garrett_core.enrollment.Proofs.approve_key_exact",
    "aivm_secrets_garrett_core.enrollment.Proofs.approve_key_contract",
    "aivm_secrets_garrett_core.enrollment.Proofs.authorize_client_contract",
    "aivm_secrets_garrett_core.enrollment.Proofs.enroll_client_contract",
    "aivm_secrets_garrett_core.enrollment.Proofs.tpm_substitution_never_signed",
    "aivm_secrets_garrett_core.enrollment.Proofs.unapproved_software_key_never_signed",
    "aivm_secrets_garrett_core.enrollment.Proofs.software_is_not_tpm",
    "aivm_secrets_garrett_core.enrollment.Proofs.tpm_plan_uses_attested_key",
    "aivm_secrets_garrett_core.enrollment.Proofs.enroll_client_successful",
    "aivm_secrets_garrett_core.enrollment.Proofs.authorize_tpm_success",
]

THEOREMS += [
    "aivm_secrets_garrett_core.authority.Proofs.require_peer_contract",
    "aivm_secrets_garrett_core.authority.Proofs.inactive_peer_denied",
    "aivm_secrets_garrett_core.authority.Proofs.wrong_peer_denied",
    "aivm_secrets_garrett_core.authority.Proofs.software_cannot_satisfy_tpm",
    "aivm_secrets_garrett_core.authority.Proofs.unrecorded_cannot_satisfy_tpm",
    "aivm_secrets_garrett_core.authority.Proofs.revoke_contract",
    "aivm_secrets_garrett_core.authority.Proofs.revoked_peer_never_admitted",
    "aivm_secrets_garrett_core.authority.Proofs.revoke_prevents_admission",
    "aivm_secrets_garrett_core.authority.Proofs.expired_peer_denied",
    "aivm_secrets_garrett_core.authority.Proofs.attested_peer_positive_witness",
    "aivm_secrets_garrett_core.authority.Proofs.commit_change_contract",
    "aivm_secrets_garrett_core.authority.Proofs.intent_failure_never_publishes",
    "aivm_secrets_garrett_core.authority.Proofs.staging_failure_never_publishes",
    "aivm_secrets_garrett_core.authority.Proofs.publication_failure_is_uncertain",
    "aivm_secrets_garrett_core.authority.Proofs.completion_failure_is_uncertain",
    "aivm_secrets_garrett_core.authority.Proofs.commit_change_positive_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.trust.Proofs.bytes_eq_spec",
    "aivm_secrets_garrett_core.trust.Proofs.bytes_eq_exact",
    "aivm_secrets_garrett_core.trust.Proofs.require_root_exact",
    "aivm_secrets_garrett_core.trust.Proofs.changed_root_fences_old_authority",
    "aivm_secrets_garrett_core.trust.Proofs.recovery_phase_contract",
    "aivm_secrets_garrett_core.trust.Proofs.changed_enrollments_refuse_recovery",
    "aivm_secrets_garrett_core.trust.Proofs.activation_without_retirement_refused",
    "aivm_secrets_garrett_core.trust.Proofs.unchanged_recovery_positive",
    "aivm_secrets_garrett_core.trust.Proofs.retired_recovery_positive",
    "aivm_secrets_garrett_core.trust.Proofs.activated_recovery_positive",
    "aivm_secrets_garrett_core.trust.Proofs.stale_root_never_changes_trust",
    "aivm_secrets_garrett_core.trust.Proofs.commit_trust_contract",
    "aivm_secrets_garrett_core.trust.Proofs.intent_failure_preserves_trust",
    "aivm_secrets_garrett_core.trust.Proofs.stage_failure_never_retires",
    "aivm_secrets_garrett_core.trust.Proofs.retirement_failure_never_activates",
    "aivm_secrets_garrett_core.trust.Proofs.activation_failure_reports_uncertainty",
    "aivm_secrets_garrett_core.trust.Proofs.completion_failure_reports_uncertainty",
    "aivm_secrets_garrett_core.trust.Proofs.trust_change_positive",
]

THEOREMS += [
    "aivm_secrets_garrett_core.oauth_state.Proofs.unsent_classification",
    "aivm_secrets_garrett_core.oauth_state.Proofs.invalid_grant_requires_reauthorization",
    "aivm_secrets_garrett_core.oauth_state.Proofs.ambiguous_sent_is_uncertain",
    "aivm_secrets_garrett_core.oauth_state.Proofs.not_sent_preserves_prior",
    "aivm_secrets_garrett_core.oauth_state.Proofs.uncertain_never_restores_ready",
    "aivm_secrets_garrett_core.oauth_state.Proofs.rejection_requires_reauthorization",
    "aivm_secrets_garrett_core.oauth_state.Proofs.permit_refresh_contract",
    "aivm_secrets_garrett_core.oauth_state.Proofs.in_doubt_needs_explicit_retry",
    "aivm_secrets_garrett_core.oauth_state.Proofs.rejection_cannot_be_overridden",
    "aivm_secrets_garrett_core.oauth_state.Proofs.revoked_never_refreshes",
    "aivm_secrets_garrett_core.oauth_state.Proofs.lease_contract",
    "aivm_secrets_garrett_core.oauth_state.Proofs.changed_epoch_fences_lease",
    "aivm_secrets_garrett_core.oauth_state.Proofs.changed_generation_fences_lease",
    "aivm_secrets_garrett_core.oauth_state.Proofs.unsettled_grant_cannot_dispatch",
    "aivm_secrets_garrett_core.oauth_state.Proofs.expired_grant_cannot_dispatch",
    "aivm_secrets_garrett_core.oauth_state.Proofs.lease_positive_witness",
    "aivm_secrets_garrett_core.oauth_state.Proofs.refresh_order_contract",
    "aivm_secrets_garrett_core.oauth_state.Proofs.intent_failure_never_sends",
    "aivm_secrets_garrett_core.oauth_state.Proofs.quarantine_failure_never_sends",
    "aivm_secrets_garrett_core.oauth_state.Proofs.uncertain_exchange_never_settles",
    "aivm_secrets_garrett_core.oauth_state.Proofs.failed_commit_never_returns_token",
    "aivm_secrets_garrett_core.oauth_state.Proofs.refresh_positive_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.oauth_state.Proofs.current_lease_contract",
    "aivm_secrets_garrett_core.oauth_state.Proofs.revoked_current_session_rejected",
    "aivm_secrets_garrett_core.oauth_state.Proofs.reenrollment_fences_current_session",
    "aivm_secrets_garrett_core.oauth_state.Proofs.unsettled_current_session_cannot_dispatch",
    "aivm_secrets_garrett_core.oauth_state.Proofs.expired_current_session_cannot_dispatch",
    "aivm_secrets_garrett_core.oauth_state.Proofs.current_session_generation_independent",
    "aivm_secrets_garrett_core.oauth_state.Proofs.renewed_current_session_positive_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.oauth_login.Proofs.bytes_ne_exact",
    "aivm_secrets_garrett_core.oauth_login.Proofs.current_contract",
    "aivm_secrets_garrett_core.oauth_login.Proofs.claim_contract",
    "aivm_secrets_garrett_core.oauth_login.Proofs.accepted_requires_exact_state",
    "aivm_secrets_garrett_core.oauth_login.Proofs.accepted_requires_issuer_policy",
    "aivm_secrets_garrett_core.oauth_login.Proofs.accepted_requires_current_window",
    "aivm_secrets_garrett_core.oauth_login.Proofs.consumed_callback_cannot_be_claimed_again",
    "aivm_secrets_garrett_core.oauth_login.Proofs.begin_contract",
    "aivm_secrets_garrett_core.oauth_login.Proofs.exchange_cannot_be_started_twice",
    "aivm_secrets_garrett_core.oauth_login.Proofs.denial_never_exchanges",
    "aivm_secrets_garrett_core.oauth_login.Proofs.unclaimed_never_exchanges",
    "aivm_secrets_garrett_core.oauth_login.Proofs.expired_callback_never_exchanges",
    "aivm_secrets_garrett_core.oauth_login.Proofs.finish_contract",
    "aivm_secrets_garrett_core.oauth_login.Proofs.failed_install_is_uncertain",
    "aivm_secrets_garrett_core.oauth_login.Proofs.complete_never_reexchanges",
    "aivm_secrets_garrett_core.oauth_login.Proofs.uncertain_never_reexchanges",
    "aivm_secrets_garrett_core.oauth_login.Proofs.successful_callback_witness",
    "aivm_secrets_garrett_core.oauth_login.Proofs.successful_exchange_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.manifest.Proofs.index_exact",
    "aivm_secrets_garrett_core.manifest.Proofs.parameter_contract",
    "aivm_secrets_garrett_core.manifest.Proofs.integer_choice_is_in_allowlist",
    "aivm_secrets_garrett_core.manifest.Proofs.text_choice_is_in_allowlist",
    "aivm_secrets_garrett_core.manifest.Proofs.range_never_exceeds_authority",
    "aivm_secrets_garrett_core.manifest.Proofs.body_never_exceeds_authority",
    "aivm_secrets_garrett_core.manifest.Proofs.integer_out_of_bounds_denied",
    "aivm_secrets_garrett_core.manifest.Proofs.type_confusion_denied",
    "aivm_secrets_garrett_core.manifest.Proofs.authorize_contract",
    "aivm_secrets_garrett_core.manifest.Proofs.writes_need_host_permission",
    "aivm_secrets_garrett_core.manifest.Proofs.request_cannot_select_other_operation",
    "aivm_secrets_garrett_core.manifest.Proofs.stale_grant_cannot_dispatch",
    "aivm_secrets_garrett_core.manifest.Proofs.release_exact",
    "aivm_secrets_garrett_core.manifest.Proofs.discarded_response_noninterference",
    "aivm_secrets_garrett_core.manifest.Proofs.range_positive_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.disclosure.Proofs.field_loop_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.field_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.ignored_field_value_cannot_affect_lookup",
    "aivm_secrets_garrett_core.disclosure.Proofs.lookup_from_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.lookup_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.charge_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.nonzero_cons",
    "aivm_secrets_garrett_core.disclosure.Proofs.text_safe_loop_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.text_safe_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.bytes_clone_exact",
    "aivm_secrets_garrett_core.disclosure.Proofs.map_eq_of_fits",
    "aivm_secrets_garrett_core.disclosure.Proofs.view_injective",
    "aivm_secrets_garrett_core.disclosure.Proofs.runItems_cons",
    "aivm_secrets_garrett_core.disclosure.Proofs.array_step_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.runItems_nil",
    "aivm_secrets_garrett_core.disclosure.Proofs.array_from_loop_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.array_from_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.runFields_cons",
    "aivm_secrets_garrett_core.disclosure.Proofs.runFields_nil",
    "aivm_secrets_garrett_core.disclosure.Proofs.field_step_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.fields_from_loop_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.fields_from_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.project_fields_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.findField_denial",
    "aivm_secrets_garrett_core.disclosure.Proofs.lookupList_denial",
    "aivm_secrets_garrett_core.disclosure.Proofs.boundedLookup_denial",
    "aivm_secrets_garrett_core.disclosure.Proofs.project_contract",
    "aivm_secrets_garrett_core.disclosure.Proofs.result_matches_unique",
    "aivm_secrets_garrett_core.disclosure.Proofs.refProject_lookup_congruence",
    "aivm_secrets_garrett_core.disclosure.Proofs.selected_path_noninterference",
    "aivm_secrets_garrett_core.disclosure.Proofs.fieldsWith_congruence",
    "aivm_secrets_garrett_core.disclosure.Proofs.root_fields_noninterference",
    "aivm_secrets_garrett_core.disclosure.Proofs.ignored_input_field_noninterference",
    "aivm_secrets_garrett_core.disclosure.Proofs.boolean_projection_positive_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.disclosure.Proofs.itemsWith_relational",
    "aivm_secrets_garrett_core.disclosure.Proofs.refProject_agreement",
    "aivm_secrets_garrett_core.disclosure.Proofs.recursive_projection_noninterference",
]

THEOREMS += [
    "aivm_secrets_garrett_core.reflection.Proofs.matches_at_contract",
    "aivm_secrets_garrett_core.reflection.Proofs.contains_from_step",
    "aivm_secrets_garrett_core.reflection.Proofs.contains_loop_contract",
    "aivm_secrets_garrett_core.reflection.Proofs.contains_contract",
    "aivm_secrets_garrett_core.reflection.Proofs.reflected_credential_is_detected",
    "aivm_secrets_garrett_core.reflection.Proofs.false_search_excludes_literal",
    "aivm_secrets_garrett_core.reflection.Proofs.nonempty_self_is_detected",
]

THEOREMS += [
    "aivm_secrets_garrett_core.client_material.Proofs.publish_request_contract",
    "aivm_secrets_garrett_core.client_material.Proofs.failed_key_never_reaches_csr",
    "aivm_secrets_garrett_core.client_material.Proofs.failed_key_is_csr_independent",
    "aivm_secrets_garrett_core.client_material.Proofs.csr_failure_retains_uncertainty",
    "aivm_secrets_garrett_core.client_material.Proofs.key_uncertainty_is_not_erased",
    "aivm_secrets_garrett_core.client_material.Proofs.success_requires_both_acknowledgements",
    "aivm_secrets_garrett_core.client_material.Proofs.successful_request_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.emission.Proofs.rejected_before_emission",
    "aivm_secrets_garrett_core.emission.Proofs.denied_emission_independent",
    "aivm_secrets_garrett_core.emission.Proofs.admitted_continuation",
    "aivm_secrets_garrett_core.emission.Proofs.emission_contract",
    "aivm_secrets_garrett_core.emission.Proofs.successful_emission_witness",
    "aivm_secrets_garrett_core.protocol.Proofs.recheck_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.recheck_rejection",
    "aivm_secrets_garrett_core.protocol.Proofs.recheck_successful_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.coordination.Proofs.rejected_before_provider",
    "aivm_secrets_garrett_core.coordination.Proofs.reservation_refusal_prevents_provider",
    "aivm_secrets_garrett_core.coordination.Proofs.provider_failure_propagated",
    "aivm_secrets_garrett_core.coordination.Proofs.failed_completion_is_uncertain",
    "aivm_secrets_garrett_core.coordination.Proofs.read_success_witness",
    "aivm_secrets_garrett_core.coordination.Proofs.write_success_witness",
    "aivm_secrets_garrett_core.coordination.Proofs.write_acknowledgement_contract",
]

THEOREMS += [
    "aivm_secrets_garrett_core.rebinding.Proofs.permitted_contract",
    "aivm_secrets_garrett_core.rebinding.Proofs.permitted_exact",
    "aivm_secrets_garrett_core.rebinding.Proofs.same_identity_and_key_required",
    "aivm_secrets_garrett_core.rebinding.Proofs.stale_target_epoch_refused",
    "aivm_secrets_garrett_core.rebinding.Proofs.changed_target_certificate_refused",
    "aivm_secrets_garrett_core.rebinding.Proofs.changed_key_refused",
    "aivm_secrets_garrett_core.rebinding.Proofs.inactive_target_refused",
    "aivm_secrets_garrett_core.rebinding.Proofs.expired_target_refused",
    "aivm_secrets_garrett_core.rebinding.Proofs.denied_before_open_or_issue",
    "aivm_secrets_garrett_core.rebinding.Proofs.open_failure_never_issues",
    "aivm_secrets_garrett_core.rebinding.Proofs.same_secret_reissuance_contract",
    "aivm_secrets_garrett_core.rebinding.Proofs.successful_rebind_witness",
]

THEOREMS += [
    "aivm_secrets_garrett_core.http_auth.Proofs.visible_from_step",
    "aivm_secrets_garrett_core.http_auth.Proofs.valid_credential_loop_contract",
    "aivm_secrets_garrett_core.http_auth.Proofs.valid_credential_contract",
    "aivm_secrets_garrett_core.http_auth.Proofs.extend_bytes_contract",
    "aivm_secrets_garrett_core.http_auth.Proofs.invalid_credential_leaves_buffer_unchanged",
    "aivm_secrets_garrett_core.http_auth.Proofs.accepted_header_exact",
    "aivm_secrets_garrett_core.http_auth.Proofs.valid_credential_has_no_crlf",
    "aivm_secrets_garrett_core.http_auth.Proofs.header_is_single_line",
    "aivm_secrets_garrett_core.http_auth.Proofs.accepted_header_cannot_split",
    "aivm_secrets_garrett_core.http_auth.Proofs.successful_header_requires_valid_credential",
    "aivm_secrets_garrett_core.http_auth.Proofs.valid_credential_positive_witness",
    "aivm_secrets_garrett_core.http_auth.Proofs.successful_header_witness",
]

THEOREMS += [
    'aivm_secrets_garrett_core.http_request.Proofs.slice_bytes_equal',
    'aivm_secrets_garrett_core.http_request.Proofs.valid_method_contract',
    'aivm_secrets_garrett_core.http_request.Proofs.target_bytes_step',
    'aivm_secrets_garrett_core.http_request.Proofs.target_loop_contract',
    'aivm_secrets_garrett_core.http_request.Proofs.valid_target_loop0_contract',
    'aivm_secrets_garrett_core.http_request.Proofs.valid_target_loop1_contract',
    'aivm_secrets_garrett_core.http_request.Proofs.valid_target_contract',
    'aivm_secrets_garrett_core.http_request.Proofs.invalid_line_leaves_buffer_unchanged',
    'aivm_secrets_garrett_core.http_request.Proofs.accepted_line_exact',
    'aivm_secrets_garrett_core.http_request.Proofs.successful_line_requires_validation',
    'aivm_secrets_garrett_core.http_request.Proofs.valid_target_has_no_delimiters',
    'aivm_secrets_garrett_core.http_request.Proofs.line_has_only_fixed_delimiters',
    'aivm_secrets_garrett_core.http_request.Proofs.accepted_line_cannot_split',
    'aivm_secrets_garrett_core.http_request.Proofs.valid_line_positive_witness',
    'aivm_secrets_garrett_core.http_request.Proofs.successful_line_witness',
]

THEOREMS += [
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.peer_bytes_equal',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.peer_from_step',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.peer_from_zero',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.contains_peer_loop_contract',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.contains_peer_contract',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.require_operator_contract',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.activate_existing_rejected',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.activate_new_exact',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.admit_contract',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.revoke_contract',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.revoked_result_is_inactive',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.revocation_denies_every_peer',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.preemptive_revocation_exact',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.reserve_new_exact',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.existing_key_is_spent',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.finish_contract',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.successful_finish_preserves_digest',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.principal_step_preserves_tombstone',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.principal_history_preserves_tombstone',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.no_future_member_admission_after_revocation',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.member_admission_positive_witness',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.matching_finish_exact',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.reservation_step_preserves_spent',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.reservation_history_preserves_spent',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.no_future_reservation_of_spent_key',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.operator_admission_positive_witness',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.require_operator_exact',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.require_operator_for_exact',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.authorize_exact',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.operator_without_membership_denied',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.member_without_operator_denied',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.every_member_action_denied_after_revocation',
    'aivm_secrets_garrett_core.coordinator_authority.Proofs.every_action_authorization_positive_witness',
]

THEOREMS += [
    'aivm_secrets_garrett_core.http_wire.Proofs.digit_value',
    'aivm_secrets_garrett_core.http_wire.Proofs.digits_length_bound',
    'aivm_secrets_garrett_core.http_wire.Proofs.decimal_value_append_digit',
    'aivm_secrets_garrett_core.http_wire.Proofs.decimal_value_exact',
    'aivm_secrets_garrett_core.http_wire.Proofs.append_decimal_exact',
    'aivm_secrets_garrett_core.http_wire.Proofs.ascii_lower_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.alphanumeric_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.prefix_tail_step',
    'aivm_secrets_garrett_core.http_wire.Proofs.ascii_prefix_loop_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.ascii_prefix_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.ascii_equal_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.ascii_equal_exact',
    'aivm_secrets_garrett_core.http_wire.Proofs.ascii_prefix_exact',
    'aivm_secrets_garrett_core.http_wire.Proofs.lifted_array_slice',
    'aivm_secrets_garrett_core.http_wire.Proofs.bool_result_choice',
    'aivm_secrets_garrett_core.http_wire.Proofs.bool_choice_truth',
    'aivm_secrets_garrett_core.http_wire.Proofs.reserved_name_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_length',
    'aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val',
    'aivm_secrets_garrett_core.http_wire.Proofs.append_headers_loop_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.append_headers_exact',
    'aivm_secrets_garrett_core.http_wire.Proofs.byte_range_step',
    'aivm_secrets_garrett_core.http_wire.Proofs.byte_range_loop_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.host_from_step',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_host_loop_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_host_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_accept_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.max_body_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.max_body_exact',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_body_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.slice_index_exact',
    'aivm_secrets_garrett_core.http_wire.Proofs.name_from_step',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_name_loop_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_name_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_value_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_header_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.unique_before_loop_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.unique_before_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_headers_loop_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_headers_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.valid_start_sound',
    'aivm_secrets_garrett_core.http_wire.Proofs.admitted_grammar',
    'aivm_secrets_garrett_core.http_wire.Proofs.decimal_wire_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.line_wire_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.authentication_wire_contract',
    'aivm_secrets_garrett_core.http_wire.Proofs.refused_start_preserves_buffer',
    'aivm_secrets_garrett_core.http_wire.Proofs.refused_credential_preserves_buffer',
    'aivm_secrets_garrett_core.http_wire.Proofs.refused_body_preserves_buffer',
    'aivm_secrets_garrett_core.http_wire.Proofs.refused_headers_preserve_buffer',
    'aivm_secrets_garrett_core.http_wire.Proofs.rejected_request_preserves_buffer',
    'aivm_secrets_garrett_core.http_wire.Proofs.successful_request_requires_admission',
    'aivm_secrets_garrett_core.http_wire.Proofs.accepted_request_exact',
]

TESTS = [
    "tests/test_rust_garrett.py",
    "tests/test_rust_garrett_tpm.py",
    "tests/test_rust_garrett_provider.py",
    "tests/test_rust_garrett_certificates.py",
    "tests/test_rust_garrett_authority.py",
    "tests/test_rust_garrett_lifecycle.py",
    "tests/test_rust_garrett_issuance.py",
    "tests/test_rust_garrett_oauth_vault.py",
    "tests/test_rust_oauth_current_session.py",
    "tests/test_rust_garrett_login.py",
    "tests/test_rust_garrett_manifest.py",
    "tests/test_rust_policy_normalization.py",
    "tests/test_rust_http_auth.py",
    "tests/test_rust_http_request.py",
    "tests/test_rust_http_wire.py",
    "tests/test_rust_garrett_reflection.py",
    "tests/test_rust_garrett_client_material.py",
    "tests/test_rust_garrett_tpm_request.py",
    "tests/test_rust_garrett_dispatch.py",
    "tests/test_rust_coordination.py",
    "tests/test_rust_coordinator_authority.py",
    "tests/test_rust_bound_renewal.py",
    "tests/test_rust_w6_adapter.py",
    "tests/test_secrets_coordination.py",
    "tests/test_secrets_garrett_modularity.py",
    "tests/test_secrets_identity_parity.py",
    "tests/test_secrets_identity_registry_parity.py",
    "tests/test_secrets_identity_renewal_parity.py",
    "tests/test_secrets_identity_revoke_cas_parity.py",
    "tests/test_secrets_authority_parity.py",
    "tests/test_secrets_identity_key_rotation_parity.py",
    "tests/test_secrets_vm_parity.py",
    "tests/test_secrets_garrett_oauth_parity.py",
]
RUNNERS = {
    "AIVM_SECRETS_RUST_GARRETT_RUNNER": "garrett-conformance",
    "AIVM_SECRETS_RUST_GARRETT_BRIDGE": "garrett-bridge",
    "AIVM_SECRETS_RUST_GARRETT_CLIENT": "garrett-client",
    "AIVM_SECRETS_RUST_IDENTITY_RUNNER": "identity-conformance",
    "AIVM_SECRETS_RUST_REGISTRY_RUNNER": "registry-conformance",
    "AIVM_SECRETS_RUST_AUTHORITY_RUNNER": "authority-conformance",
    "AIVM_SECRETS_RUST_AUTHORITY_ADMIN": "garrett-authority",
    "AIVM_SECRETS_RUST_KEY_ROTATION_RUNNER": "key-rotation-conformance",
    "AIVM_SECRETS_RUST_VM_RUNNER": "vm-conformance",
    "AIVM_SECRETS_RUST_OAUTH_RUNNER": "oauth-conformance",
    "AIVM_SECRETS_RUST_OAUTH_ADMIN": "garrett-oauth",
    "AIVM_SECRETS_RUST_MANIFEST_RUNNER": "manifest-conformance",
    "AIVM_SECRETS_RUST_COORDINATOR": "garrett-coordinator",
}


def inputs() -> list[str]:
    files = {
        ".github/workflows/garrett.yml",
        "MANIFEST.in",
        "pyproject.toml",
        "rust/Cargo.toml",
        "rust/Cargo.lock",
        "rust/rust-toolchain.toml",
        "proofs/lakefile.lean",
        "proofs/lean-toolchain",
        "proofs/lake-manifest.json",
        "proofs/manifest.json",
        "proofs/generated/AivmSecretsGarrettCore.lean",
        "proofs/Garrett.lean",
        "proofs/GarrettFoundation.lean",
        "proofs/GarrettSecrecy.lean",
        "proofs/GarrettCheck.lean",
        "proofs/GarrettProtocol.lean",
        "proofs/GarrettHistory.lean",
        "proofs/GarrettEnrollment.lean",
        "proofs/GarrettAuthority.lean",
        "proofs/GarrettTrust.lean",
        "proofs/GarrettOAuth.lean",
        "proofs/GarrettLogin.lean",
        "proofs/GarrettManifest.lean",
        "proofs/GarrettDisclosure.lean",
        "proofs/GarrettReflection.lean",
        "proofs/GarrettClientMaterial.lean",
        "proofs/GarrettEmission.lean",
        "proofs/GarrettCoordination.lean",
        "proofs/GarrettRebinding.lean",
        "proofs/GarrettHttpAuth.lean",
        "proofs/GarrettHttpRequest.lean",
        "proofs/GarrettHttpWireDecimal.lean",
        "proofs/GarrettHttpWireHeaders.lean",
        "proofs/GarrettHttpWireFormatting.lean",
        "proofs/GarrettHttpWireValidation.lean",
        "proofs/GarrettHttpWire.lean",
        "proofs/GarrettCoordinatorAuthority.lean",
        "tests/secrets_vectors/coordination/authority-v1.jsonl",
        "proofs/GarrettProfiles.lean",
        "tests/limited_exec.py",
        "dev/verification/garrett.py",
        "dev/verification/freshness.py",
        "tests/secrets_helpers.py",
        "tests/test_secrets_identity_mtls.py",
        *TESTS,
    }
    for name in ["aivm-secrets-garrett", "aivm-secrets-garrett-core"]:
        directory = ROOT / "rust/crates" / name
        files.add(str((directory / "Cargo.toml").relative_to(ROOT)))
        files.update(str(p.relative_to(ROOT)) for p in directory.rglob("*.rs"))
    files.update(
        str(p.relative_to(ROOT)) for p in (ROOT / "aivm_secrets").rglob("*.py")
    )
    for pattern in ["*.jsonl", "*.json"]:
        files.update(
            str(p.relative_to(ROOT))
            for p in (ROOT / "tests/secrets_vectors").glob(pattern)
        )
    return sorted(files)


def extract(destination: Path, rust_root: Path | None = None) -> Path:
    rust_root = ROOT / "rust" if rust_root is None else rust_root
    base.run(
        [
            base.TOOLS / "charon",
            "cargo",
            "--preset=aeneas",
            "--sysroot",
            "default",
            "--",
            "--lib",
            "--locked",
        ],
        cwd=rust_root / "crates/aivm-secrets-garrett-core",
    )
    destination.mkdir(parents=True, exist_ok=True)
    base.run(
        [
            base.TOOLS / "aeneas",
            "-backend",
            "lean",
            "-no-progress-bar",
            "-loops-to-rec",
            "-abort-on-error",
            "-warnings-as-errors",
            "-dest",
            destination,
            rust_root / "aivm_secrets_garrett_core.llbc",
        ]
    )
    generated = destination / "AivmSecretsGarrettCore.lean"
    if not generated.is_file():
        raise SystemExit("missing extracted Garrett module")
    return generated


def regeneration() -> None:
    with tempfile.TemporaryDirectory(
        prefix="garrett-extract-", dir=ROOT / ".tools"
    ) as scratch:
        generated = extract(Path(scratch))
        if (
            generated.read_bytes()
            != (PROOFS / "generated" / generated.name).read_bytes()
        ):
            raise SystemExit("Garrett extraction is stale; regenerate and review it")


def audit(output: str) -> None:
    found = {}
    for name, axioms in re.findall(
        r"'([^']+)' depends on axioms:\s*\[([^\]]*)\]", output
    ):
        found[name] = {item.strip() for item in axioms.split(",") if item.strip()}
    for name in re.findall(r"'([^']+)' does not depend on any axioms", output):
        found[name] = set()
    if set(found) != set(THEOREMS):
        raise SystemExit(
            f"theorem audit inventory differs: {set(found) ^ set(THEOREMS)}"
        )
    for name, axioms in found.items():
        if axioms - base.ALLOWED_AXIOMS:
            raise SystemExit(
                f"{name}: undeclared axioms {axioms - base.ALLOWED_AXIOMS}"
            )
    print(
        f"Audited {len(found)} named Garrett obligations; no admitted or project-specific security axiom.",
        flush=True,
    )


def prove() -> None:
    base.run([base.executable("lake"), "build"], cwd=PROOFS)
    result = base.run(
        [
            base.executable("lake"),
            "env",
            "lean",
            "-DwarningAsError=true",
            "GarrettCheck.lean",
        ],
        cwd=PROOFS,
        capture=True,
    )
    print(result.stdout, end="")
    audit(result.stdout)


def parity() -> None:
    base.run(
        [base.executable("cargo"), "+" + base.RUST, "fmt", "--all", "--", "--check"],
        cwd=ROOT / "rust",
    )
    for mode in ["--no-default-features", "--all-features"]:
        base.run(
            [
                base.executable("cargo"),
                "+" + base.RUST,
                "clippy",
                "--locked",
                "-p",
                "aivm-secrets-garrett",
                "--all-targets",
                mode,
                "--",
                "-D",
                "warnings",
            ],
            cwd=ROOT / "rust",
        )
    base.run(
        [
            base.executable("cargo"),
            "+" + base.RUST,
            "build",
            "--locked",
            "--release",
            "-p",
            "aivm-secrets-garrett",
            "--all-features",
        ],
        cwd=ROOT / "rust",
    )
    base.run(
        [
            base.executable("cargo"),
            "+" + base.RUST,
            "test",
            "--locked",
            "-p",
            "aivm-secrets-garrett",
            "--lib",
            "--all-features",
        ],
        cwd=ROOT / "rust",
    )
    env = dict(
        os.environ,
        **{
            name: str(ROOT / "rust/target/release" / program)
            for name, program in RUNNERS.items()
        },
    )
    env["AIVM_SECRETS_REQUIRE_TPM_TESTS"] = "1"
    base.run([sys.executable, "-m", "pytest", "-q", *TESTS], env=env)


def assurance_coordinates() -> dict:
    return {
        "schema": 1,
        "protocol": "nested Garrett surrogate profile v1",
        "profiles": PROFILES,
        "rust": base.RUST,
        "lean": base.LEAN,
        "aeneas_release": base.RELEASE,
        "theorems": THEOREMS,
        "allowed_axioms": sorted(base.ALLOWED_AXIOMS),
        "implementation_linked": "Aeneas-generated optional coordinator dispatch continuation and issuance, request preparation/observation/use/release, key-approval/client-enrollment, current-peer/assurance/revocation, exact root-fencing/recovery-prefix ordered authority/trust-publication and durable-before-send OAuth refresh/lease and one-shot callback/code-exchange lifecycle controllers; exact byte/epoch/time decisions, manifest parameter membership/ranges and operation/write guards, and typed public-result projection, including exact recursive manifest filtering, schema-directed two-run noninterference and exact borrowed-byte literal-reflection search, plus ordered client private-key/CSR publication and uncertainty propagation, final admission-before-emission and repeated exact protocol admission, and concrete authentication-header credential validation/exact byte appending and request-line method/target validation/exact single-line construction used by both native provider writers, extended to complete request framing with Host/Accept, exact custom-header ordering, case-insensitive reserved/duplicate refusal, concrete decimal port/body length and exact opaque body bytes; optional coordinator authority exact peer/operator admission, absent-only activation, revocation/reservation/completion decisions and modeled terminal committed-decision histories",
        "symbolic_model": "Dolev-Yao encrypted-message deduction, protected-signature origin and public protocol traces; conditional source-controller issuance/dispatch histories",
        "assumptions": [
            "Charon/Aeneas translation and supplied standard models, Lean kernel, Rust compiler and target ABI are trusted.",
            "Signature verification authenticates the exact envelope; sealing/unsealing implement their stated cryptographic contracts.",
            "ring AES-GCM/Ed25519/SHA-256, rustls/webpki, OS entropy and nonce discipline are trusted, not cryptographically re-proved.",
            "TLS peer evidence comes only from the completed certificate-verified connection; registry/trust inputs come from the trusted host.",
            "Independent-use prevention assumes no access to the enrolled signing/client oracle; non-exportability alone is insufficient.",
            "Symbolic secrecy assumes protected keys and the specified provider disclosure contract; lengths and public claims are observable.",
            "The legacy bridge uses the existing trusted local broker; account-status-v1 uses the Rust custody/executor and its declared id/active disclosure contract.",
            "Reply noninterference holds when parsed provider public fields agree; providers, errors, timing and metadata may disclose information outside that contract.",
            "TPM tools and silicon/emulator command semantics are trusted; the restricted AK pin must be independently provisioned and oracle access controlled.",
            "The native observer acknowledges only a complete, flushed record under the exclusive-writer and trusted host/filesystem assumptions; acknowledgement is not a client field.",
            "Presentation uses trusted entry/enrollment/clock snapshots; cross-process dispatch linearization and whole-service concurrent traces remain open.",
            "Native authority admission holds a shared flock through dispatch; participating administrators take its exclusive lease. Held directory/file checks, atomic rename and fsync implement assumed storage contracts, not a proved filesystem or anti-rollback boundary. Legacy independent-file bridges retain entry-snapshot semantics.",
            "TPM assurance receipts are trusted principal-owned host metadata bound to subject, certificate and SPKI. Missing receipts never imply TPM assurance; older Python administrators do not enforce the new assurance-downgrade policy.",
            "Trust recovery requires a reviewed public-plan digest, exact authority/keyring/enrollment prefix and complete immutable material. Hashing/serialization, key-file validation, durable retirement and activation are trusted storage adapters; no snapshot-rollback resistance or whole-filesystem refinement is claimed.",
            "Native file issuance acknowledges public claims before atomic no-replace output publication under a held authority lease. Private output storage and explicit delivery are trusted host operations; publication/completion errors may leave a usable file and require reconciliation.",
            "OAuth quarantine and successor persistence are conditional storage-adapter contracts. Native vault locking drains participating refresh/revoke against dispatch and HMAC checks token equality; root snapshot rollback, hostile same-UID replacement and nonparticipating writers are outside that boundary.",
            "Native PKCE login trusts entropy, SHA-256 S256 derivation, HTTP/query decoding and loopback listener/clock adapters. Callback binding and one-shot lifecycle guards are extracted; ready URLs go only to a trusted host operator/browser, and their state/challenge must not be offered as an agent API. Concrete acquisition I/O histories and secret-sink refinement remain open.",
            "Native OAuth sessions seal an opaque vault/provider/subject/epoch-bound marker and select the current ready token under a held vault lock. Explicit refresh may change its generation without changing the grant deadline. HMAC/entropy, lock participation, concrete opener correspondence and clock sampling remain adapter contracts; this is not a whole-service or concurrent filesystem proof.",
            "The optional native coordinator authority retains Python's SQLite schema and mTLS endpoint. Exact operator/member matching and terminal principal/reservation decision histories are extracted and proved; HTTP parsing, authenticated DER-to-hex conversion, row conversion, SQL bindings, commit-before-reply placement, SQLite WAL/FULL durability, concurrency and complete native I/O refinement remain separate library/environment or project-owned adapter obligations. There is no replica, live inode replacement or rollback witness, and no positive admission cache or automatic retry.",
            "Native coordinated account/manifest sessions trust the separately authenticated SQLite coordinator for terminal membership decisions and durable globally unique reservations. The extracted dispatch controller requires admission/reservation acknowledgements before invoking a provider and maps failed post-send completion to uncertainty. TLS/HTTP, server durability/rollback, last-check linearization and concrete callback placement remain adapter premises. Native coordinated request fingerprints hash a canonical document rebuilt from parsed policy, with independent Python differential and real durable-record tests. Policy normalization, JSON encoding and SHA-256 remain concrete adapters; finite tests do not establish all-input digest equivalence or broad core parity.",
            "Privileged same-key rebinding carries the identical opened opaque broker capability to the existing issuer. Source signature/AEAD, current-CA historical certificate fingerprints, protected owner-only inputs, shared authority lease participation and no-replace publication remain adapter contracts. This is an explicit host authorization, not acceptance of an expired guest JWT; the broker grant and terminal coordinator checks still apply.",
            "The extracted complete HTTP request encoder checks public field grammar, reserved/duplicate headers and credential/body admission before changing the buffer, with exact successful bytes under an explicit modeled capacity premise. The production caller supplies route/effect fields and canonical JSON in a zeroizing buffer. Their mapping/serialization, destination selection, TLS, response parsing, memory erasure, provider behavior and whole-service I/O mediation remain separate obligations.",
            "The manifest HTTPS backend trusts the policy/check/template/GraphQL parsers, JSON-to-typed-tree conversion and selected-tree rendering, reflection traversal/call sites and concrete HTTP/audit ordering. Exact borrowed-byte literal search is extracted and proved. The extracted recursive filter matches an independent selection specification and has exact two-run noninterference under recursive schema agreement; unselected typed-tree fields are unconstrained. These contracts do not refine the remaining adapters or establish arbitrary provider non-disclosure or whole-service trace equivalence. Native configuration explicitly selects unbounded requests and a file source or explicit OAuth override.",
            "Native provider emission rechecks authority and current OAuth token expiry after audit, TLS setup and request construction. The extracted continuation refuses emission on a failed recheck; setup placement, trusted clock sampling, live lease stability and concrete socket writes remain tested adapter contracts. Control admission follows the credential lease wait and checks the outer as well as inner lifetime.",
            "Native TPM CSR creation reuses the validated pinned-key signer and verifies its returned possession request. Local TPM attributes and signatures do not establish hardware provenance; independent fresh attestation approval under a trusted AK remains required. The new CSR, TPM command and JSON/file adapters are tested, not newly formally refined.",
            "Native software client bootstrap trusts entropy, P-256/CSR/SPKI adapters and held-directory no-replace file publication/durability. The extracted controller proves key acknowledgement before CSR publication and conservative uncertainty; it does not prove the filesystem, private-key memory erasure, signing or CLI I/O. Existing material is never automatically replaced or adopted, and software requests assert no TPM or VM provenance.",
            "Controller histories assume signature verification has prior recorded issuer origin; the ideal signature-origin theorem does not establish a computational byte-level or concrete I/O refinement.",
            "CSR possession, CA constraints/key matching and X.509 signing use the stated rcgen/x509-parser/time adapter contracts; their ASN.1/crypto implementations are not formally refined. TPM approval consumes verified fresh evidence under a trusted AK pin.",
        ],
        "exclusions": [
            "Proof of Python or all-input cross-language equivalence",
            "Formal refinement of JSON, TLS, X.509, crypto, TPM evidence, HTTP and filesystem adapter implementations",
            "Physical TPM provenance, EK activation, PCR/firmware policy and anti-rollback deployment",
            "Provider non-disclosure, host compromise, snapshot rollback and side channels",
            "Complete Rust policy/credential administration, client aliases, command resolvers, approvals/delegation, TPM material provisioning and concrete storage/concurrent-history refinement",
        ],
    }


def check_manifest() -> None:
    # Shared tool/model/compiler identities are pinned by the independently
    # checked freshness manifest; no duplicate drifting provisioner is needed.
    base.check_hashes(json.loads(base.MANIFEST.read_text()))
    manifest = json.loads(MANIFEST.read_text())
    expected = assurance_coordinates()
    if set(manifest) != set(expected) | {"sha256"}:
        raise SystemExit("Garrett manifest metadata inventory differs")
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise SystemExit(f"Garrett assurance coordinate differs: {key}")
    if (
        manifest["theorems"] != THEOREMS
        or set(manifest["allowed_axioms"]) != base.ALLOWED_AXIOMS
    ):
        raise SystemExit("Garrett theorem or axiom policy differs")
    if (
        manifest["rust"] != base.RUST
        or manifest["lean"] != base.LEAN
        or manifest["aeneas_release"] != base.RELEASE
    ):
        raise SystemExit("Garrett toolchain pins differ")
    if set(manifest["sha256"]) != set(inputs()):
        raise SystemExit("Garrett manifest source coverage differs")
    for name, expected in manifest["sha256"].items():
        if base.sha256(ROOT / name) != expected:
            raise SystemExit(f"Garrett manifest is stale: {name}")


def record() -> None:
    base.check_hashes(json.loads(base.MANIFEST.read_text()))
    regeneration()
    prove()
    parity()
    manifest = assurance_coordinates()
    manifest["sha256"] = {name: base.sha256(ROOT / name) for name in inputs()}
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Recorded checked Garrett source, assumptions and proof coordinates.")


def mutate(pattern: str | None = None) -> None:
    source = ROOT / "rust/crates/aivm-secrets-garrett-core/src/lib.rs"
    changes = [
        ("missing peer binding", "|| claims.certificate != *peer", "|| false"),
        ("missing current epoch", "|| claims.epoch != expected.epoch", "|| false"),
        ("inclusive expiry", "now >= claims.expires_at", "now > claims.expires_at"),
        ("inactive enrollment", "!active || epoch < 0", "false || epoch < 0"),
        (
            "bypassed binding before unseal",
            "present(&envelope.claims, expected, peer, now)",
            "Ok::<(), Denial>(())",
        ),
        (
            "unissued token",
            "issuer.seal(&claims, secret)",
            "Ok::<Vec<u8>, Denial>(Vec::new())",
        ),
    ]
    mutations = [(source, *change) for change in changes]
    use_source = source.with_name("credential_use.rs")
    mutations += [
        (
            use_source,
            "missing inner binding",
            "|| claims.binding != current.binding",
            "|| false",
        ),
        (
            use_source,
            "bypassed credential authorization",
            "authorize_use(claims, grant, operation, now, elapsed)",
            "Ok::<(), UseDenial>(())",
        ),
        (
            use_source,
            "substituted provider route",
            "executor.execute(route, credential)",
            "executor.execute(&Route { host: Vec::new(), port: 443, path: Vec::new(), authentication: Authentication::Bearer }, credential)",
        ),
        (
            use_source,
            "private response length released",
            "account_id: reply.account_id,",
            "account_id: reply.discarded.len() as i64,",
        ),
    ]
    protocol_source = source.with_name("protocol.rs")
    mutations += [
        (
            protocol_source,
            "unrecorded issuance released",
            "observer.issued(&issued.claims)",
            "Ok::<(), Denial>(())",
        ),
        (
            protocol_source,
            "substituted issuance record",
            "observer.issued(&issued.claims)",
            "observer.issued(&Claims { issuer: Vec::new(), audience: Vec::new(), subject: Vec::new(), token_id: Vec::new(), certificate: Vec::new(), epoch: 0, issued_at: 0, expires_at: 1 })",
        ),
        (
            protocol_source,
            "composed authorization bypass",
            "authorize_use(\n        &inner.claims,\n        grant,\n        operation,\n        presentation.now,\n        presentation.elapsed,\n    )",
            "Ok::<(), UseDenial>(())",
        ),
        (
            protocol_source,
            "unrecorded composed dispatch",
            "observer.record(&ready.identity, &ready.claims, &grant.route, operation)",
            "Ok::<(), UseDenial>(())",
        ),
        (
            protocol_source,
            "substituted recorded identity",
            "observer.record(&ready.identity, &ready.claims, &grant.route, operation)",
            "observer.record(&Claims { certificate: Vec::new(), ..ready.identity }, &ready.claims, &grant.route, operation)",
        ),
        (
            protocol_source,
            "composed route substitution",
            "finish_use(executor, &ready.credential, &grant.route)",
            "finish_use(executor, &ready.credential, &Route { host: Vec::new(), port: 443, path: Vec::new(), authentication: crate::credential_use::Authentication::Bearer })",
        ),
    ]
    enrollment_source = source.with_name("enrollment.rs")
    mutations += [
        (
            enrollment_source,
            "TPM CSR key substitution accepted",
            "candidate.spki != *spki",
            "false",
        ),
        (
            enrollment_source,
            "software approval bypass",
            "candidate.fingerprint != *fingerprint",
            "false",
        ),
        (
            enrollment_source,
            "software assurance escalated",
            "Ok(Assurance::OperatorApproved)",
            "Ok(Assurance::AttestedTpm)",
        ),
        (
            enrollment_source,
            "approved client key replaced",
            "spki: input.candidate.spki,",
            "spki: Vec::new(),",
        ),
        (
            enrollment_source,
            "client expiry beyond CA",
            "not_after >= input.ca_not_after",
            "false",
        ),
        (
            enrollment_source,
            "client approval bypassed before signing",
            "authorize_client(input, approval)",
            "Ok::<ClientPlan, EnrollmentDenial>(ClientPlan { subject: input.subject, spki: input.candidate.spki, not_before: input.now, not_after: input.now, assurance: Assurance::AttestedTpm })",
        ),
    ]
    authority_source = source.with_name("authority.rs")
    mutations += [
        (
            authority_source,
            "current peer binding removed",
            "*certificate != *peer",
            "false",
        ),
        (
            authority_source,
            "expired authority admission accepted",
            "now >= not_after",
            "now > not_after",
        ),
        (
            authority_source,
            "software escalated at authority admission",
            "Requirement::AttestedTpm => match assurance {",
            "Requirement::AttestedTpm => match &Assurance::Tpm {",
        ),
        (
            authority_source,
            "revocation leaves client active",
            "active: false,",
            "active: true,",
        ),
        (
            authority_source,
            "authority intent bypassed",
            "store.intent()",
            "Ok::<(), StorageFailure>(())",
        ),
        (
            authority_source,
            "authority material staging bypassed",
            "store.stage()",
            "Ok::<(), StorageFailure>(())",
        ),
        (
            authority_source,
            "authority publication bypassed",
            "store.publish()",
            "Ok::<(), StorageFailure>(())",
        ),
        (
            authority_source,
            "published change reported unchanged",
            "if let Err(_) = store.complete() {\n        return Err(CommitDenial::OutcomeUnknown);",
            "if let Err(_) = store.complete() {\n        return Err(CommitDenial::Unpublished);",
        ),
    ]
    trust_source = source.with_name("trust.rs")
    mutations += [
        (trust_source, "changed trust root accepted", "*current != *expected", "false"),
        (
            trust_source,
            "changed enrollments accepted for recovery",
            "if *registry == *before_registry {",
            "if true {",
        ),
        (
            trust_source,
            "activation without retired enrollments accepted",
            "*anchor == *after_anchor && *registry == *after_registry",
            "*anchor == *after_anchor",
        ),
        (
            trust_source,
            "trust material staging bypassed",
            "store.stage()",
            "Ok::<(), StorageFailure>(())",
        ),
        (
            trust_source,
            "enrollment retirement bypassed",
            "store.retire()",
            "Ok::<(), StorageFailure>(())",
        ),
        (
            trust_source,
            "activation moved before retirement",
            "if let Err(_) = store.retire() {\n        return Err(TrustDenial::OutcomeUnknown);\n    }\n    if let Err(_) = store.activate() {",
            "if let Err(_) = store.activate() {\n        return Err(TrustDenial::OutcomeUnknown);\n    }\n    if let Err(_) = store.retire() {",
        ),
        (
            trust_source,
            "retirement failure reported unchanged",
            "if let Err(_) = store.retire() {\n        return Err(TrustDenial::OutcomeUnknown);",
            "if let Err(_) = store.retire() {\n        return Err(TrustDenial::Unpublished);",
        ),
        (
            trust_source,
            "completed trust change reported unchanged",
            "if let Err(_) = store.complete() {\n        return Err(TrustDenial::OutcomeUnknown);",
            "if let Err(_) = store.complete() {\n        return Err(TrustDenial::Unpublished);",
        ),
    ]
    oauth_source = source.with_name("oauth_state.rs")
    mutations += [
        (
            oauth_source,
            "OAuth silent retry of in-doubt refresh",
            "if !retry_in_doubt {",
            "if false {",
        ),
        (
            oauth_source,
            "OAuth reauthorization bypass",
            "RefreshState::Reauthorize => return Err(RefreshDenial::Unsettled),",
            "RefreshState::Reauthorize => (),",
        ),
        (
            oauth_source,
            "OAuth uncertain result restores ready",
            "ExchangeFailure::Uncertain => RefreshState::InDoubt,",
            "ExchangeFailure::Uncertain => RefreshState::Ready,",
        ),
        (
            oauth_source,
            "OAuth definite-not-sent clears prior doubt",
            "RefreshState::InDoubt => RefreshState::InDoubt,",
            "RefreshState::InDoubt => RefreshState::Ready,",
        ),
        (
            oauth_source,
            "OAuth refresh quarantine omitted",
            "ops.quarantine()",
            "Ok::<(), StoreFailure>(())",
        ),
        (
            oauth_source,
            "OAuth successor persistence omitted",
            "ops.commit(&successor)",
            "Ok::<(), StoreFailure>(())",
        ),
        (
            oauth_source,
            "OAuth exchange before quarantine",
            "if let Err(_) = ops.quarantine() {\n        return Err(RefreshDenial::Uncertain);\n    }\n    match ops.exchange() {",
            "let exchanged = ops.exchange();\n    if let Err(_) = ops.quarantine() {\n        return Err(RefreshDenial::Uncertain);\n    }\n    match exchanged {",
        ),
        (
            oauth_source,
            "OAuth stale generation accepted",
            "|| current.generation != leased.generation",
            "|| false",
        ),
        (
            oauth_source,
            "OAuth stale epoch accepted",
            "|| current.epoch != leased.epoch",
            "|| false",
        ),
        (
            oauth_source,
            "OAuth expired lease accepted",
            "now >= current.expires_at",
            "now > current.expires_at",
        ),
    ]
    mutations += [
        (
            oauth_source,
            "current session epoch rebound to current vault",
            "epoch: expected_epoch,",
            "epoch: current.epoch,",
        ),
    ]
    login_source = source.with_name("oauth_login.rs")
    mutations += [
        (
            login_source,
            "login callback state bypass",
            "if callback.state != pending.state {",
            "if false {",
        ),
        (
            login_source,
            "login missing required issuer accepted",
            "if !callback.has_issuer || callback.issuer != *expected {",
            "if callback.issuer != *expected {",
        ),
        (
            login_source,
            "login issuer substitution accepted",
            "if !callback.has_issuer || callback.issuer != *expected {",
            "if !callback.has_issuer {",
        ),
        (
            login_source,
            "login unexpected issuer accepted",
            "if callback.has_issuer {",
            "if false {",
        ),
        (
            login_source,
            "login inclusive callback expiry",
            "now >= pending.expires_at",
            "now > pending.expires_at",
        ),
        (
            login_source,
            "login consumed callback accepted again",
            "Stage::Pending => (),",
            "Stage::Pending | Stage::Accepted => (),",
        ),
        (
            login_source,
            "login unclaimed code exchanged",
            "Stage::Accepted => (),",
            "Stage::Accepted | Stage::Pending => (),",
        ),
        (
            login_source,
            "login code exchanged twice",
            "Stage::Accepted => (),",
            "Stage::Accepted | Stage::Exchanging => (),",
        ),
        (
            login_source,
            "login denial treated as code",
            "if callback.denied {\n        Ok(Stage::Denied)",
            "if callback.denied {\n        Ok(Stage::Accepted)",
        ),
        (
            login_source,
            "login failed install treated as complete",
            "Ok(Stage::Uncertain)",
            "Ok(Stage::Complete)",
        ),
        (
            login_source,
            "login completion before exchange",
            "Stage::Exchanging => (),",
            "Stage::Exchanging | Stage::Accepted => (),",
        ),
    ]
    header_source = source.with_name("http_auth.rs")
    mutations += [
        (header_source, "http auth empty credential accepted", "secret.len() == 0", "false"),
        (header_source, "http auth oversized credential accepted", "secret.len() > 4096", "false"),
        (header_source, "http auth control byte accepted", "*byte < b'!'", "false"),
        (header_source, "http auth nonascii byte accepted", "*byte > b'~'", "false"),
        (header_source, "http auth guard omitted", "!valid_credential(secret)", "false"),
        (header_source, "http auth wrong selected header",
         'Authentication::Bearer => output.extend_from_slice(b"Authorization: Bearer "),',
         'Authentication::Bearer => output.extend_from_slice(b"Authorization: Basic "),'),
        (header_source, "http auth credential substituted", "output.extend_from_slice(secret);", 'output.extend_from_slice(b"REPLACED");'),
        (header_source, "http auth malformed terminator", 'output.extend_from_slice(b"\\r\\n");', 'output.extend_from_slice(b"\\n");'),
    ]
    request_source = source.with_name("http_request.rs")
    mutations += [
        (request_source, "http request empty target accepted", "target.len() == 0", "false"),
        (request_source, "http request oversized target accepted", "target.len() > 8192", "false"),
        (request_source, "http request absolute target accepted", "target[0] != b'/'", "false"),
        (request_source, "http request network target accepted", "target[1] == b'/'", "false"),
        (request_source, "http request control delimiter accepted", "*byte < b'!'", "false"),
        (request_source, "http request nonascii target accepted", "*byte > b'~'", "false"),
        (request_source, "http request fragment accepted", "*byte == b'#'", "false"),
        (request_source, "http request method guard omitted", "!valid_method(method)", "false"),
        (request_source, "http request target guard omitted", "!valid_target(target)", "false"),
        (request_source, "http request selected target substituted", "output.extend_from_slice(target);", 'output.extend_from_slice(b"/REPLACED");'),
        (request_source, "http request malformed version delimiter",
         'output.extend_from_slice(b" HTTP/1.1\\r\\n");',
         'output.extend_from_slice(b" HTTP/1.1\\n");'),
    ]
    wire_source = source.with_name("http_wire.rs")
    mutations += [
        (wire_source, "http wire case folding altered", "byte + 32", "byte + 31"),
        (wire_source, "http wire right operand not folded", "ascii_lower(prefix[i])", "prefix[i]"),
        (wire_source, "http wire reserved header admitted", "!reserved_name(name)", "true"),
        (wire_source, "http wire duplicate name admitted", "!unique_before(headers, i, &headers[i].name)", "false"),
        (wire_source, "http wire start validation omitted", "if !valid_start(head)", "if false"),
        (wire_source, "http wire credential validation omitted", "if !http_auth::valid_credential(secret)", "if false"),
        (wire_source, "http wire body validation omitted", "if !valid_body(body)", "if false"),
        (wire_source, "http wire header validation omitted", "if !valid_headers(&head.headers)", "if false"),
        (wire_source, "http wire decimal digit changed", "b'0' + (value % 10) as u8", "b'1' + (value % 10) as u8"),
        (wire_source, "http wire destination port substituted", "append_decimal(output, head.port as usize);", "append_decimal(output, 443);"),
        (wire_source, "http wire body length overstated", "append_decimal(output, bytes.len());", "append_decimal(output, bytes.len() + 1);"),
        (wire_source, "http wire body discarded", "output.extend_from_slice(bytes);", "let _ = bytes;"),
        (wire_source, "http wire credential copied outside authentication",
         "http_auth::append_header(output, secret, authentication)\n        .map_err(|_| EncodingDenial::InvalidCredential)?;",
         "http_auth::append_header(output, secret, authentication)\n        .map_err(|_| EncodingDenial::InvalidCredential)?;\n    output.extend_from_slice(secret);"),
    ]
    authority_source = source.with_name("coordinator_authority.rs")
    mutations += [
        (authority_source, "coordinator dispatch operator classification omitted",
         "Action::Activate | Action::Revoke | Action::Status => require_operator(operators, peer),",
         "Action::Activate | Action::Revoke | Action::Status => Ok(()),"),
        (authority_source, "coordinator dispatch final operator check omitted",
         "require_operator_for(action, operators, peer)?;", "let _ = operators;"),
        (authority_source, "coordinator dispatch member check omitted",
         "Action::Check | Action::Reserve | Action::Finish => Ok(Some(admit(current, peer)?)),",
         "Action::Check | Action::Reserve | Action::Finish => Ok(Some(1)),"),
        (authority_source, "coordinator dispatch reservation requires operator instead of member",
         "Action::Check | Action::Reserve | Action::Finish => Ok(()),",
         "Action::Reserve => require_operator(operators, peer), Action::Check | Action::Finish => Ok(()),"),
        (authority_source, "coordinator authority wrong peer equality", "*member == *peer", "*member != *peer"),
        (authority_source, "coordinator authority operator gate bypass", "!contains_peer(operators, peer)", "false"),
        (authority_source, "coordinator authority existing principal reactivated",
         "Some(_) => Err(Denial::Revoked),",
         "Some(_) => Ok(Principal { active: true, members, revision: 1 }),"),
        (authority_source, "coordinator authority preemptive tombstone active", "active: false,", "active: true,"),
        (authority_source, "coordinator authority revoked row active", "principal.active = false;", "principal.active = true;"),
        (authority_source, "coordinator authority inactive principal admitted", "!principal.active", "false"),
        (authority_source, "coordinator authority wrong member admitted", "!contains_peer(&principal.members, peer)", "false"),
        (authority_source, "coordinator authority spent key reserved again",
         "Some(_) => Err(Denial::OutcomeUnknown),",
         "Some(_) => Ok(Reservation { digest, completed: false }),"),
        (authority_source, "coordinator authority mismatched digest finished", "row.digest != *digest", "false"),
        (authority_source, "coordinator authority completion not recorded", "row.completed = true;", "row.completed = false;"),
    ]
    manifest_source = source.with_name("manifest.rs")
    mutations += [
        (manifest_source, "manifest lower range escaped", "*value < *lo", "false"),
        (manifest_source, "manifest upper range escaped", "*value > *hi", "false"),
        (
            manifest_source,
            "manifest integer membership bypass",
            "(Rule::Integers(allowed), Scalar::Integer(value)) => {\n            if witness >= allowed.len() || allowed[witness] != *value",
            "(Rule::Integers(allowed), Scalar::Integer(value)) => {\n            if witness >= allowed.len()",
        ),
        (
            manifest_source,
            "manifest text membership bypass",
            "(Rule::Texts(allowed), Scalar::Text(value)) => {\n            if witness >= allowed.len() || allowed[witness] != *value",
            "(Rule::Texts(allowed), Scalar::Text(value)) => {\n            if witness >= allowed.len()",
        ),
        (
            manifest_source,
            "manifest unchecked integer index",
            "(Rule::Integers(allowed), Scalar::Integer(value)) => {\n            if witness >= allowed.len() ||",
            "(Rule::Integers(allowed), Scalar::Integer(value)) => {\n            if",
        ),
        (
            manifest_source,
            "manifest body authority bypass",
            "value.len() > *maximum",
            "false",
        ),
        (
            manifest_source,
            "manifest type confusion",
            "_ => return Err(UseDenial::Denied)",
            "_ => return Ok(())",
        ),
        (
            manifest_source,
            "manifest stale grant accepted",
            "require_use_current(claims, grant, now, elapsed)",
            "Ok::<(), UseDenial>(())",
        ),
        (
            manifest_source,
            "manifest operation substitution",
            "*requested != *selected",
            "false",
        ),
        (
            manifest_source,
            "manifest host write gate bypass",
            "write && !writes_allowed",
            "false",
        ),
        (
            manifest_source,
            "manifest discarded provider response released",
            "reply.selected",
            "reply.discarded",
        ),
    ]
    disclosure_source = source.with_name("disclosure.rs")
    mutations += [
        (
            disclosure_source,
            "disclosure lookup accepts wrong key",
            "if entry.0 != *name {",
            "if entry.0 == *name {",
        ),
        (
            disclosure_source,
            "disclosure exits selected path early",
            "if index >= at.len() {",
            "if index <= at.len() {",
        ),
        (
            disclosure_source,
            "disclosure accepts embedded zero",
            "if value[index] == 0 {",
            "if value[index] != 0 {",
        ),
        (
            disclosure_source,
            "disclosure corrupts integer leaf",
            "value: Json::Integer(*v),",
            "value: Json::Integer(0),",
        ),
        (
            disclosure_source,
            "disclosure replaces schema output name",
            "out.push((field.name.clone(), selected.value));",
            "out.push((Vec::new(), selected.value));",
        ),
        (
            disclosure_source,
            "disclosure projects from wrong object",
            "project_fields(selected, fields, fuel - 1, budget)",
            "project_fields(value, fields, fuel - 1, budget)",
        ),
        (
            disclosure_source,
            "disclosure skips first array item",
            "array_from(values, item, fuel - 1, charge(budget, 2)?, 0, Vec::new())",
            "array_from(values, item, fuel - 1, charge(budget, 2)?, 1, Vec::new())",
        ),
        (
            disclosure_source,
            "disclosure corrupts object child",
            "out.push((field.name.clone(), selected.value));",
            "out.push((field.name.clone(), Json::Null));",
        ),
        (
            disclosure_source,
            "disclosure bypasses depth termination",
            "if fuel == 0 {",
            "if false {",
        ),
        (
            disclosure_source,
            "disclosure permits empty field schema",
            "if fields.len() == 0 || fields.len() > 32 {",
            "if fields.len() > 32 {",
        ),
    ]
    reflection_source = source.with_name("reflection.rs")
    mutations += [
        (
            reflection_source,
            "reflection comparison inverted",
            "value[start..start + secret.len()] == *secret",
            "value[start..start + secret.len()] != *secret",
        ),
        (
            reflection_source,
            "reflection last offset skipped",
            "while start <= last {",
            "while start < last {",
        ),
        (
            reflection_source,
            "reflection first offset skipped",
            "let mut start = 0;",
            "let mut start = 1;",
        ),
        (
            reflection_source,
            "reflection equal-length secret skipped",
            "if secret.len() == 0 || secret.len() > value.len() {",
            "if secret.len() == 0 || secret.len() >= value.len() {",
        ),
        (
            reflection_source,
            "reflection alternating offsets skipped",
            "start += 1;",
            "start += 2;",
        ),
    ]
    material_source = source.with_name("client_material.rs")
    mutations += [
        (
            material_source,
            "client key publication bypassed",
            "match store.write_key() {",
            "match Ok::<(), PublishFailure>(()) {",
        ),
        (
            material_source,
            "client key uncertainty erased",
            "Err(error) => return Err(error),",
            "Err(_) => return Err(PublishFailure::Unpublished),",
        ),
        (
            material_source,
            "client CSR failure reported unchanged",
            "Err(_) => Err(PublishFailure::OutcomeUnknown),",
            "Err(_) => Err(PublishFailure::Unpublished),",
        ),
        (
            material_source,
            "client CSR failure reported successful",
            "Err(_) => Err(PublishFailure::OutcomeUnknown),",
            "Err(_) => Ok(()),",
        ),
        (
            material_source,
            "client CSR published before private key",
            "match store.write_key() {\n        Ok(()) => (),\n        Err(error) => return Err(error),\n    }\n    match store.write_csr() {",
            "match store.write_csr() {\n        Ok(()) => (),\n        Err(error) => return Err(error),\n    }\n    match store.write_key() {",
        ),
    ]
    mutations += [
        (
            source.with_name("emission.rs"),
            "late admission omitted",
            "    match pending.recheck() {\n        Ok(()) => (),\n        Err(error) => return Err(error),\n    }",
            "    let _admitted = ();",
        ),
        (
            source.with_name("emission.rs"),
            "late admission denial ignored",
            "    match pending.recheck() {\n        Ok(()) => (),\n        Err(error) => return Err(error),\n    }",
            "    let _ignored = pending.recheck();",
        ),
        (
            source.with_name("protocol.rs"),
            "late protocol checks omitted",
            "    match prepare(verifier, opener, token, grant, operation, presentation) {\n        Ok(_) => Ok(()),\n        Err(error) => Err(error),\n    }",
            "    Ok(())",
        ),
        (
            source.with_name("protocol.rs"),
            "late protocol denial reported admitted",
            "    match prepare(verifier, opener, token, grant, operation, presentation) {\n        Ok(_) => Ok(()),\n        Err(error) => Err(error),\n    }",
            "    match prepare(verifier, opener, token, grant, operation, presentation) {\n        Ok(_) => Ok(()),\n        Err(_) => Ok(()),\n    }",
        ),
    ]
    coordinated = source.with_name("coordination.rs")
    mutations += [
        (coordinated, "coordinated admission bypass", "ops.check()", "Ok::<(), D::Error>(())"),
        (coordinated, "coordinated reservation bypass", "ops.reserve()", "Ok::<(), D::Error>(())"),
        (coordinated, "coordinated completion bypass", "ops.finish()", "Ok::<(), D::Error>(())"),
        (coordinated, "coordinated failed completion reports success",
         "Err(_) => return Err(ops.outcome_unknown()),", "Err(_) => (),"),
    ]
    rebinding = source.with_name("rebinding.rs")
    mutations += [
        (rebinding, "rebind same-key check omitted", "&& *source_key == target.key", "&& true"),
        (rebinding, "rebind subject check omitted", "&& source.subject == target.identity.subject", "&& true"),
        (rebinding, "rebind target epoch CAS omitted", "&& target.identity.epoch == expected_epoch", "&& true"),
        (rebinding, "rebind target certificate CAS omitted", "&& target.certificate == *expected_certificate", "&& true"),
        (rebinding, "rebind target expiry omitted", "&& now < target.not_after", "&& true"),
        (rebinding, "rebind backwards epoch accepted", "&& source.epoch <= target.identity.epoch", "&& true"),
        (rebinding, "rebind inactive target accepted", "    target.active\n", "    true\n"),
        (rebinding, "rebind admission before open bypassed", "if !permitted(", "if false && !permitted("),
    ]
    total = len(mutations)
    if pattern is not None:
        mutations = [mutation for mutation in mutations if re.search(pattern, mutation[1])]
        if not mutations:
            raise SystemExit("no security mutations match the selected filter")
    print(f"Selected {len(mutations)} of {total} security mutations; filter={pattern!r}", flush=True)
    lean_path = base.run(
        [base.executable("lake"), "env", "printenv", "LEAN_PATH"],
        cwd=PROOFS,
        capture=True,
    ).stdout.strip()
    lean_path = os.pathsep.join(
        str((PROOFS / part).resolve()) for part in lean_path.split(os.pathsep)
    )

    def check_mutation(mutation) -> None:
        source, label, old, new = mutation
        if source.read_text().count(old) != 1:
            raise SystemExit(f"mutation no longer matches once: {label}")
        with tempfile.TemporaryDirectory(
            prefix="garrett-mutant-", dir=ROOT / ".tools"
        ) as scratch:
            temporary = Path(scratch)
            rust = temporary / "rust"
            shutil.copytree(
                source.parents[1], rust / "crates/aivm-secrets-garrett-core"
            )
            shutil.copy2(
                ROOT / "rust/rust-toolchain.toml", rust / "rust-toolchain.toml"
            )
            (rust / "Cargo.toml").write_text(
                '[workspace]\nmembers=["crates/aivm-secrets-garrett-core"]\nresolver="2"\n[workspace.package]\nversion="0.1.0"\nedition="2021"\nlicense="Apache-2.0"\n'
            )
            (rust / "Cargo.lock").write_text(
                'version = 4\n[[package]]\nname="aivm-secrets-garrett-core"\nversion="0.1.0"\n'
            )
            target = rust / "crates/aivm-secrets-garrett-core/src" / source.name
            target.write_text(source.read_text().replace(old, new))
            extract(temporary, rust)
            env = dict(os.environ, LEAN_PATH=str(temporary) + os.pathsep + lean_path)
            lean = [
                base.executable("elan"),
                "run",
                base.LEAN,
                "lean",
                "-DwarningAsError=true",
            ]
            base.run(
                [
                    *lean,
                    "-o",
                    temporary / "AivmSecretsGarrettCore.olean",
                    temporary / "AivmSecretsGarrettCore.lean",
                ],
                cwd=temporary,
                env=env,
            )
            rejected = False
            modules = [
                "Garrett",
                "GarrettProtocol",
                "GarrettHistory",
                "GarrettEnrollment",
                "GarrettAuthority",
                "GarrettTrust",
                "GarrettOAuth",
                "GarrettLogin",
                "GarrettManifest",
                "GarrettDisclosure",
                "GarrettReflection",
                "GarrettClientMaterial",
                "GarrettEmission",
                "GarrettCoordination",
                "GarrettRebinding",
                "GarrettHttpAuth",
                "GarrettHttpRequest",
                "GarrettHttpWireDecimal",
                "GarrettHttpWireHeaders",
                "GarrettHttpWireFormatting",
                "GarrettHttpWireValidation",
                "GarrettHttpWire",
                "GarrettCoordinatorAuthority",
            ]
            # These leaves import the extracted crate plus generic standard-
            # model facts. Check the affected leaf first; keep full fallback
            # coverage and dependency order for all other protocol modules.
            preferred = {
                "enrollment.rs": "GarrettEnrollment",
                "authority.rs": "GarrettAuthority",
                "trust.rs": "GarrettTrust",
                "oauth_state.rs": "GarrettOAuth",
                "oauth_login.rs": "GarrettLogin",
                "reflection.rs": "GarrettReflection",
                "client_material.rs": "GarrettClientMaterial",
                "emission.rs": "GarrettEmission",
                "coordination.rs": "GarrettCoordination",
                "rebinding.rs": "GarrettRebinding",
                "http_auth.rs": "GarrettHttpAuth",
                "http_request.rs": "GarrettHttpRequest",
                "http_wire.rs": "GarrettHttpWireDecimal",
                "coordinator_authority.rs": "GarrettCoordinatorAuthority",
            }.get(source.name)
            if preferred:
                modules.remove(preferred)
                modules.insert(0, preferred)
            if source.name == "manifest.rs":
                modules.remove("GarrettLogin")
                modules.remove("GarrettManifest")
                modules[1:1] = ["GarrettLogin", "GarrettManifest"]
            if source.name == "disclosure.rs":
                for dependency in [
                    "GarrettLogin",
                    "GarrettManifest",
                    "GarrettDisclosure",
                ]:
                    modules.remove(dependency)
                modules[1:1] = ["GarrettLogin", "GarrettManifest", "GarrettDisclosure"]
            for module in modules:
                proof = temporary / (module + ".lean")
                shutil.copy2(PROOFS / proof.name, proof)
                result = base.run(
                    [
                        *lean,
                        "-DmaxErrors=1",
                        "-o",
                        temporary / (module + ".olean"),
                        proof,
                    ],
                    cwd=temporary,
                    env=env,
                    capture=True,
                    check=False,
                )
                if result.returncode == 0:
                    continue
                infrastructure = any(
                    x in result.stdout
                    for x in [
                        "unknown module prefix",
                        "does not exist",
                        "cannot find file",
                    ]
                )
                resources = any(
                    x in (result.stdout + result.stderr).lower()
                    for x in [
                        "timeout",
                        "heartbeats",
                        "maximum recursion depth",
                        "out of memory",
                        "stack overflow",
                        "interrupted",
                    ]
                )
                if (
                    infrastructure
                    or resources
                    or not re.search(rf"{module}\.lean:\d+:\d+: error:", result.stdout)
                ):
                    raise SystemExit(
                        f"mutant failed for an unexpected reason: {label}\n{result.stdout}\n{result.stderr}"
                    )
                print(result.stdout, end="")
                print(
                    f"Lean rejected re-extracted Rust mutation: {label} ({module})",
                    flush=True,
                )
                rejected = True
                break
            if not rejected:
                raise SystemExit(f"mutant survived the proofs: {label}")

    # Each mutant has its own Rust workspace and Lean search/output directory.
    # Shared proof/model caches are read-only after the successful baseline.
    with ThreadPoolExecutor(max_workers=min(4, os.cpu_count() or 1)) as pool:
        list(pool.map(check_mutation, mutations))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["bootstrap", "extract", "record", "check", "mutate"]
    )
    parser.add_argument("--mutation-filter", help="Run only labels matching this regex; never counts as the full mutation campaign.")
    args = parser.parse_args()
    if args.mutation_filter is not None and args.action != "mutate":
        parser.error("--mutation-filter requires the mutate action")
    if args.action == "bootstrap":
        base.bootstrap()
    elif args.action == "extract":
        extract(PROOFS / "generated")
    elif args.action == "record":
        record()
    else:
        check_manifest()
        regeneration()
        prove()
        if args.action == "mutate":
            mutate(args.mutation_filter)
        else:
            parity()


if __name__ == "__main__":
    main()
