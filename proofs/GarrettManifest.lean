import GarrettLogin

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.oauth_login.Proofs (bytes_ne_exact)
open aivm_secrets_garrett_core.credential_use
open aivm_secrets_garrett_core.credential_use.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.manifest.Proofs

def Allowed (rule : Rule) (value : Scalar) (witness : Usize) : Prop :=
  match rule, value with
  | .Range lo hi, .Integer v => 0 ≤ lo.val ∧ lo.val ≤ hi.val ∧ lo.val ≤ v.val ∧ v.val ≤ hi.val
  | .Integers values, .Integer v => values.val[witness.val]? = some v
  | .Texts values, .Text v => values.val[witness.val]? = some v
  | .Body maximum, .Text v => 1 ≤ maximum.val ∧ v.val.length ≤ maximum.val
  | _, _ => False

theorem index_exact {α : Type} (v : alloc.vec.Vec α) (i : Usize) (bound : i.val < v.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = Result.ok (v.val[i.val]) := by
  rw [alloc.vec.Vec.index_slice_index]
  obtain ⟨out, returned, eq⟩ := returned_of_spec (alloc.vec.Vec.index_usize_spec v i bound)
  simpa only [eq] using returned

theorem parameter_contract (rule : Rule) (value : Scalar) (witness : Usize) :
    parameter rule value witness ⦃ out => out = .Ok () ↔ Allowed rule value witness ⦄ := by
  classical
  cases rule with
  | Range lo hi =>
    cases value <;> simp only [parameter]
    all_goals repeat' first | (solve | simp_all [Allowed, WP.spec_ok]; all_goals scalar_tac) | split
  | Body maximum =>
    cases value <;> simp only [parameter]
    all_goals repeat' first | (solve | simp_all [Allowed, WP.spec_ok]; all_goals scalar_tac) | split
  | Integers values =>
    cases value with
    | Text v => simp [parameter, Allowed]
    | Integer v =>
      simp only [parameter]
      split
      next outside =>
        have hb : values.val.length ≤ witness.val := by scalar_tac
        simp [Allowed, WP.spec_ok, List.getElem?_eq_none hb]
      next inside =>
        have hb : witness.val < values.length := by scalar_tac
        rw [index_exact values witness hb]
        simp only [bind_ok]
        split <;> simp_all [Allowed, WP.spec_ok]
        scalar_tac
  | Texts values =>
    cases value with
    | Integer v => simp [parameter, Allowed]
    | Text v =>
      simp only [parameter]
      split
      next outside =>
        have hb : values.val.length ≤ witness.val := by scalar_tac
        simp [Allowed, WP.spec_ok, List.getElem?_eq_none hb]
      next inside =>
        have hb : witness.val < values.length := by scalar_tac
        rw [index_exact values witness hb]
        simp [bytes_ne_exact, Allowed, List.getElem?_eq_getElem hb]
        split <;> simp_all [WP.spec_ok, eq_comm]

theorem integer_choice_is_in_allowlist (values : alloc.vec.Vec I64) (value : I64) (witness : Usize) :
    parameter (.Integers values) (.Integer value) witness ⦃ out => out = .Ok () → value ∈ values.val ⦄ := by
  apply WP.spec_mono (parameter_contract (.Integers values) (.Integer value) witness)
  intro out spec h
  exact List.mem_of_getElem? (spec.mp h)

theorem text_choice_is_in_allowlist (values : alloc.vec.Vec (alloc.vec.Vec U8)) (value : alloc.vec.Vec U8) (witness : Usize) :
    parameter (.Texts values) (.Text value) witness ⦃ out => out = .Ok () → value ∈ values.val ⦄ := by
  apply WP.spec_mono (parameter_contract (.Texts values) (.Text value) witness)
  intro out spec h
  exact List.mem_of_getElem? (spec.mp h)

theorem range_never_exceeds_authority (lo hi value : I64) (witness : Usize) :
    parameter (.Range lo hi) (.Integer value) witness ⦃ out => out = .Ok () → lo.val ≤ value.val ∧ value.val ≤ hi.val ⦄ := by
  apply WP.spec_mono (parameter_contract (.Range lo hi) (.Integer value) witness)
  intro out spec h
  exact ⟨(spec.mp h).2.2.1, (spec.mp h).2.2.2⟩

theorem body_never_exceeds_authority (maximum : Usize) (value : alloc.vec.Vec U8) (witness : Usize) :
    parameter (.Body maximum) (.Text value) witness ⦃ out => out = .Ok () → value.val.length ≤ maximum.val ⦄ := by
  apply WP.spec_mono (parameter_contract (.Body maximum) (.Text value) witness)
  intro out spec h
  exact (spec.mp h).2

theorem integer_out_of_bounds_denied (values : alloc.vec.Vec I64) (value : I64) (witness : Usize)
    (bound : values.length ≤ witness.val) :
    parameter (.Integers values) (.Integer value) witness = Result.ok (.Err .Denied) := by
  simp only [parameter]
  split
  · rfl
  · exfalso; scalar_tac

theorem type_confusion_denied (lo hi : I64) (value : alloc.vec.Vec U8) (witness : Usize) :
    parameter (.Range lo hi) (.Text value) witness = Result.ok (.Err .Denied) := by rfl

def Admission (c : UseClaims) (g : UseGrant) (requested selected : alloc.vec.Vec U8)
    (write allowed : Bool) (now elapsed : I64) : Prop :=
  Current c g now.val elapsed.val ∧ requested = selected ∧ (write = true → allowed = true)

theorem authorize_contract (c : UseClaims) (g : UseGrant) (requested selected : alloc.vec.Vec U8)
    (write allowed : Bool) (now elapsed : I64) :
    authorize c g requested selected write allowed now elapsed ⦃ out => out = .Ok () ↔
      Admission c g requested selected write allowed now elapsed ⦄ := by
  obtain ⟨checked, returned, property⟩ := returned_of_spec (require_use_current_contract c g now elapsed)
  cases checked with
  | Err e => cases e <;> simp_all [authorize, Admission, WP.spec_ok]
  | Ok u =>
    cases u
    cases write <;> cases allowed <;> simp_all [authorize, bytes_ne_exact, Admission, WP.spec_ok] <;>
      split <;> simp_all [WP.spec_ok]

theorem writes_need_host_permission (c : UseClaims) (g : UseGrant) (requested selected : alloc.vec.Vec U8) (now elapsed : I64) :
    authorize c g requested selected true false now elapsed ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (authorize_contract c g requested selected true false now elapsed)
  intro out spec h
  exact Bool.false_ne_true ((spec.mp h).2.2 rfl)

theorem request_cannot_select_other_operation (c : UseClaims) (g : UseGrant) (requested selected : alloc.vec.Vec U8)
    (write allowed : Bool) (now elapsed : I64) (different : requested ≠ selected) :
    authorize c g requested selected write allowed now elapsed ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (authorize_contract c g requested selected write allowed now elapsed)
  intro out spec h
  exact different (spec.mp h).2.1

theorem stale_grant_cannot_dispatch (c : UseClaims) (g : UseGrant) (requested selected : alloc.vec.Vec U8)
    (write allowed : Bool) (now elapsed : I64) (stale : ¬ Current c g now.val elapsed.val) :
    authorize c g requested selected write allowed now elapsed ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (authorize_contract c g requested selected write allowed now elapsed)
  intro out spec h
  exact stale (spec.mp h).1

theorem release_exact (reply : ProviderReply) : release reply = Result.ok reply.selected := by rfl

theorem discarded_response_noninterference (a b : ProviderReply) (same : a.selected = b.selected) :
    release a = release b := by simp [release, same]

theorem range_positive_witness (witness : Usize) :
    parameter (.Range 1#i64 9#i64) (.Integer 5#i64) witness = Result.ok (.Ok ()) := by simp [parameter]

end aivm_secrets_garrett_core.manifest.Proofs
