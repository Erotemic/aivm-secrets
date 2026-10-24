import GarrettRouteMatch

/-!
# One request target, one set of arguments (HP-6)

Source: `rust/crates/aivm-secrets-garrett-core/src/route_match.rs` and
`route.rs`, extracted by Aeneas.

`translate_round_trip` (in `GarrettRouteMatch`) says an accepted target is
exactly what the host's `fill_target` writes for the accepted arguments.
This file adds the other half of "exactly one named operation and
arguments": when every path value is a single segment (contains no `/`),
**the target determines every template value**. Two translations of the same
target, even from different candidate lists, agree on the value of every
path piece and every query parameter, so the host encodes the same request
for both.

The condition is necessary. A parameter whose allowed texts may contain `/`
can make one target mean two things: `/repos/{owner}/{repo}` writes
`/repos/a/b/c` for both `owner = a/b, repo = c` and `owner = a, repo = b/c`.
Such a route needs its own disambiguation. Either way the host bridge
authorizes whichever operation it receives, so ambiguity affects only which
allowed operation runs, never authority.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.route.Proofs
open aivm_secrets_garrett_core.http_wire.Proofs (AlphaNumeric)
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.route_match.Proofs

open aivm_secrets_garrett_core.route

/-- A path value that stays inside one segment. -/
def OneSegment (value : List U8) : Prop := ∀ byte ∈ value, byte ≠ 47#u8

/-- Every path piece's value is one segment. -/
def SingleSegments (bindings : List Binding) (path : List Piece) : Prop :=
  ∀ piece ∈ path, ∀ value, PieceValue bindings piece = some value → OneSegment value

theorem unreserved_ne {byte : U8} (h : Unreserved byte) :
    byte ≠ 47#u8 ∧ byte ≠ 63#u8 ∧ byte ≠ 38#u8 := by
  unfold Unreserved AlphaNumeric at h
  refine ⟨?_, ?_, ?_⟩ <;> intro e <;> subst e <;> simp at h

/-- A separator byte: what can follow a path value (`/`, `?`) or a query
    value (`&`). -/
def Starts (rest : List U8) : Prop :=
  rest = [] ∨ ∃ tail, rest = 47#u8 :: tail ∨ rest = 63#u8 :: tail ∨ rest = 38#u8 :: tail

def Plain (value : List U8) : Prop :=
  ∀ byte ∈ value, byte ≠ 47#u8 ∧ byte ≠ 63#u8 ∧ byte ≠ 38#u8

/-- Two plain values each followed by a separator (or the end) split one
    byte string the same way. -/
theorem split_plain : ∀ {v1 v2 r1 r2 : List U8}, Plain v1 → Plain v2 → Starts r1 → Starts r2 →
    v1 ++ r1 = v2 ++ r2 → v1 = v2 ∧ r1 = r2
  | [], [], _, _, _, _, _, _, h => ⟨rfl, by simpa using h⟩
  | [], b :: v2, r1, r2, _, p2, s1, _, h => by
      exfalso
      simp only [List.nil_append, List.cons_append] at h
      obtain ⟨n47, n63, n38⟩ := p2 b (by simp)
      rcases s1 with rfl | ⟨tail, rfl | rfl | rfl⟩ <;> simp_all
  | a :: v1, [], r1, r2, p1, _, _, s2, h => by
      exfalso
      simp only [List.nil_append, List.cons_append] at h
      obtain ⟨n47, n63, n38⟩ := p1 a (by simp)
      rcases s2 with rfl | ⟨tail, rfl | rfl | rfl⟩ <;> simp_all
  | a :: v1, b :: v2, r1, r2, p1, p2, s1, s2, h => by
      simp only [List.cons_append, List.cons.injEq] at h
      obtain ⟨rfl, rest⟩ := h
      obtain ⟨same, tails⟩ := split_plain (fun x m => p1 x (by simp [m]))
        (fun x m => p2 x (by simp [m])) s1 s2 rest
      exact ⟨by rw [same], tails⟩

theorem plain_of_path {value : List U8} (bytes : ∀ byte ∈ value, PathByte byte)
    (one : OneSegment value) : Plain value := by
  intro byte m
  rcases bytes byte m with u | slash
  · exact unreserved_ne u
  · exact absurd slash (one byte m)

theorem plain_of_seg {value : List U8} (seg : Seg value) : Plain value :=
  fun byte m => unreserved_ne (seg.2.2.2.2 byte m)

theorem query_starts (b : List Binding) (first : Bool) (query : List QueryPiece) :
    Starts (QueryBytes b first query) := by
  cases query with
  | nil => exact Or.inl rfl
  | cons e rest =>
    right
    cases first <;> simp [QueryBytes]

theorem path_starts (b : List Binding) (path : List Piece) (tail : List U8) (s : Starts tail) :
    Starts (PathBytes b path ++ tail) := by
  cases path with
  | nil => simpa [PathBytes] using s
  | cons p rest =>
    exact Or.inr ⟨(PieceValue b p).getD [] ++ (PathBytes b rest ++ tail),
      Or.inl (by simp [PathBytes])⟩

/-- The path part determines every path value. -/
theorem path_values_unique : ∀ (path : List Piece) {b1 b2 : List Binding} {t1 t2 : List U8},
    Bound b1 path → Bound b2 path → SingleSegments b1 path → SingleSegments b2 path →
    Starts t1 → Starts t2 →
    PathBytes b1 path ++ t1 = PathBytes b2 path ++ t2 →
    (∀ piece ∈ path, PieceValue b1 piece = PieceValue b2 piece) ∧ t1 = t2
  | [], _, _, _, _, _, _, _, _, _, _, h => ⟨by simp, by simpa [PathBytes] using h⟩
  | p :: rest, b1, b2, t1, t2, bd1, bd2, one1, one2, s1, s2, h => by
      obtain ⟨v1, e1, path1⟩ := bd1 p (by simp)
      obtain ⟨v2, e2, path2⟩ := bd2 p (by simp)
      have plain1 := plain_of_path path1 (one1 p (by simp) v1 e1)
      have plain2 := plain_of_path path2 (one2 p (by simp) v2 e2)
      simp only [PathBytes, e1, e2, Option.getD_some, List.cons_append, List.cons.injEq,
        true_and, List.append_assoc] at h
      obtain ⟨same, tails⟩ := split_plain plain1 plain2
        (path_starts b1 rest t1 s1) (path_starts b2 rest t2 s2) h
      obtain ⟨later, ends⟩ := path_values_unique rest
        (fun q m => bd1 q (by simp [m])) (fun q m => bd2 q (by simp [m]))
        (fun q m => one1 q (by simp [m])) (fun q m => one2 q (by simp [m])) s1 s2 tails
      refine ⟨?_, ends⟩
      intro q m
      rcases List.mem_cons.mp m with rfl | m
      · rw [e1, e2, same]
      · exact later q m

/-- The query part determines every query value. -/
theorem query_values_unique : ∀ (query : List QueryPiece) (first : Bool) {b1 b2 : List Binding},
    QueryBound b1 query → QueryBound b2 query →
    QueryBytes b1 first query = QueryBytes b2 first query →
    ∀ entry ∈ query, PieceValue b1 entry.piece = PieceValue b2 entry.piece
  | [], _, _, _, _, _, _ => by simp
  | e :: rest, first, b1, b2, q1, q2, h => by
      obtain ⟨_, v1, e1, seg1⟩ := q1 e (by simp)
      obtain ⟨_, v2, e2, seg2⟩ := q2 e (by simp)
      simp only [QueryBytes, e1, e2, Option.getD_some, List.cons.injEq, true_and,
        List.append_assoc, List.append_cancel_left_eq, List.cons_append] at h
      obtain ⟨same, tails⟩ := split_plain (plain_of_seg seg1) (plain_of_seg seg2)
        (query_starts b1 false rest) (query_starts b2 false rest) h
      intro q m
      rcases List.mem_cons.mp m with rfl | m
      · rw [e1, e2, same]
      · exact query_values_unique rest false (fun x mx => q1 x (by simp [mx]))
          (fun x mx => q2 x (by simp [mx])) tails q m

/-- **One target, one set of arguments.** Two accepted translations of the
    same target against the same templates give every path piece and every
    query parameter the same value, provided the path values are single
    segments. The candidate lists may differ: what the guest's route copy
    suggested cannot change what the target means. -/
theorem translate_unique {path : Slice Piece} {query : Slice QueryPiece}
    {c1 c2 : Slice Binding} {target : Slice U8} {b1 b2 : alloc.vec.Vec Binding}
    (h1 : translate path query c1 target = Result.ok (some b1))
    (h2 : translate path query c2 target = Result.ok (some b2))
    (one1 : SingleSegments b1.val path.val) (one2 : SingleSegments b2.val path.val) :
    (∀ piece ∈ path.val, PieceValue b1.val piece = PieceValue b2.val piece) ∧
    (∀ entry ∈ query.val, PieceValue b1.val entry.piece = PieceValue b2.val entry.piece) := by
  obtain ⟨t1, bd1, qb1, _⟩ := translate_exact h1
  obtain ⟨t2, bd2, qb2, _⟩ := translate_exact h2
  have h := t1.symm.trans t2
  obtain ⟨paths, queries⟩ := path_values_unique path.val bd1 bd2 one1 one2
    (query_starts _ true _) (query_starts _ true _) h
  exact ⟨paths, query_values_unique query.val true qb1 qb2 queries⟩

end aivm_secrets_garrett_core.route_match.Proofs
