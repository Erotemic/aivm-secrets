import GarrettHttpWireHeaders

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.http_auth.Proofs
open garrett_stateless_core.http_request.Proofs
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.http_wire.Proofs

@[simp, scalar_tac_simps]
theorem vec_deref_length {T : Type} (value : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref value).length = value.length := by simp [alloc.vec.Vec.deref]

@[simp, scalar_tac_simps]
theorem vec_deref_val {T : Type} (value : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref value).val = value.val := by simp [alloc.vec.Vec.deref]

end garrett_stateless_core.http_wire.Proofs
