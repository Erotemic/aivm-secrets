import GarrettStatelessCore
import GarrettHttpAuth

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.http_auth.Proofs
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.http_request.Proofs

@[step]
theorem slice_bytes_equal (a b : Slice U8) :
    core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b
      ⦃ out => out ↔ a.val = b.val ⦄ := by
  apply WP.spec_mono (core.slice.cmp.PartialEqSlice.eq_homo_spec
    core.cmp.PartialEqU8 a b (by intro x y; simp))
  intro out exact_bytes
  simpa [Slice.eq_iff] using exact_bytes

end garrett_stateless_core.http_request.Proofs
