import Freshness

-- The verification helper checks every name and rejects undeclared transitive
-- axioms. Missing declarations and admitted proofs must fail the gate.
#print axioms aivm_secrets_primitives.Proofs.advance_contract
#print axioms aivm_secrets_primitives.Proofs.current_exact
#print axioms aivm_secrets_primitives.Proofs.active_exact
#print axioms aivm_secrets_primitives.Proofs.fresh_exact
#print axioms aivm_secrets_primitives.Proofs.fresh_accepted_iff
#print axioms aivm_secrets_primitives.Proofs.fresh_rejects_stale
#print axioms aivm_secrets_primitives.Proofs.fresh_rejects_expired
#print axioms aivm_secrets_primitives.Proofs.advance_invalidates_old_epoch
#print axioms aivm_secrets_primitives.Proofs.fresh_positive_witness
#print axioms aivm_secrets_primitives.Proofs.advance_positive_witness
