import GarrettProxyHttp

/-!
# HTTPS proxy: what an accepted request occupies

Source: `parse_request` and its helpers in
`crates/garrett-stateless-core/src/proxy_http.rs`, extracted by
Aeneas. The proxy's tunnel loop (`proxy_controller::frame`, then the native
`buffer.drain(..parsed.used)`) consumes `used` bytes of the guest's buffer.

Proved here (`parse_request_bounds`): whenever the strict parser accepts a
request, it used no more bytes than were buffered (so the native `drain`
cannot panic) and the request body is at most the configured `limit`,
whether it was framed by `Content-Length` or chunked.

Not proved: which requests the parser accepts or how it reads fields; the
upstream encoder re-checks everything it writes (`GarrettProxyHttp`), so
header framing does not depend on the parser.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs

set_option maxHeartbeats 4000000

namespace garrett_stateless_core.proxy_http.Proofs

theorem add_eq {a b c : Usize} (h : a + b = Result.ok c) : c.val = a.val + b.val := by
  have := UScalar.add_equiv a b
  rw [h] at this
  exact this.2.1

theorem head_end_loop_spec (data : Slice U8) (small : data.length + 4 ≤ Usize.max) (index : Usize)
    (inside : index.val ≤ data.length) :
    head_end_loop data index ⦃ o => ∀ e, o = some e → e.val + 4 ≤ data.length ⦄ := by
  suffices ∀ n (index : Usize), data.length - index.val = n → index.val ≤ data.length →
      head_end_loop data index ⦃ o => ∀ e, o = some e → e.val + 4 ≤ data.length ⦄ from
    this _ index rfl inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure inside
    rw [head_end_loop.eq_def]
    step*
    -- `step*` also applies the induction hypothesis; its measure goals are
    -- closed by `rfl` and arithmetic.
    all_goals try rfl
    all_goals scalar_tac

theorem head_end_some {data : Slice U8} {e : Usize} (small : data.length + 4 ≤ Usize.max)
    (h : head_end data = Result.ok (some e)) : e.val + 4 ≤ data.length := by
  obtain ⟨o, ho, post⟩ := returned_of_spec (head_end_loop_spec data small 0#usize (by simp))
  unfold head_end at h
  rw [ho] at h
  simp only [Result.ok.injEq] at h
  exact post e h

theorem usize_holds_u32 : 4294967295 ≤ Usize.max := by scalar_tac

/-- The chunk-size loop never overflows: at most 8 hex digits. -/
theorem chunk_size_loop_spec (data : Slice U8) (stop total index start : Usize)
    (order : start.val ≤ index.val) (below : index.val ≤ stop.val) (inside : stop.val ≤ data.length)
    (short : stop.val - start.val ≤ 8) (sofar : total.val < 16 ^ (index.val - start.val)) :
    chunk_size_loop data stop total index ⦃ o => ∀ size, o = some size → size.val < 16 ^ 8 ⦄ := by
  suffices ∀ n (total index : Usize), stop.val - index.val = n → start.val ≤ index.val →
      index.val ≤ stop.val → total.val < 16 ^ (index.val - start.val) →
      chunk_size_loop data stop total index ⦃ o => ∀ size, o = some size → size.val < 16 ^ 8 ⦄ from
    this _ total index rfl order below sofar
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro total index measure lo below sofar
    rw [chunk_size_loop.eq_def]
    split
    · rename_i more
      have k_le : index.val - start.val + 1 ≤ 8 := by scalar_tac
      have pow_le : 16 ^ (index.val - start.val + 1) ≤ 16 ^ 8 := Nat.pow_le_pow_right (by norm_num) k_le
      have grow : (total.val + 1) * 16 ≤ 16 ^ (index.val - start.val + 1) := by
        rw [pow_succ]; exact Nat.mul_le_mul_right 16 sofar
      have u32 := usize_holds_u32
      step as ⟨byte, _⟩
      step as ⟨o, ho⟩
      split
      · simp only [WP.spec_ok]; intro size h; cases h
      · rename_i digit
        have small : digit.val < 16 := ho digit rfl
        step as ⟨scaled, hscaled⟩
        step as ⟨next_total, hnext_total⟩
        step as ⟨next, hnext⟩
        refine ih (stop.val - next.val) (by scalar_tac) next_total next rfl (by scalar_tac) (by scalar_tac) ?_
        have : next.val - start.val = index.val - start.val + 1 := by scalar_tac
        rw [this]
        have : next_total.val = total.val * 16 + digit.val := by scalar_tac
        rw [this]
        omega
    · simp only [WP.spec_ok]
      intro size h
      simp only [Option.some.injEq] at h
      subst h
      have : index.val - start.val ≤ 8 := by scalar_tac
      exact Nat.lt_of_lt_of_le sofar (Nat.pow_le_pow_right (by norm_num) this)

@[step]
theorem chunk_size_spec (data : Slice U8) (start stop : Usize) (inside : stop.val ≤ data.length) :
    chunk_size data start stop ⦃ o => ∀ size, o = some size → size.val < 16 ^ 8 ⦄ := by
  unfold chunk_size
  split
  · simp only [WP.spec_ok]; intro size h; cases h
  · step as ⟨width, hwidth⟩
    split
    · simp only [WP.spec_ok]; intro size h; cases h
    · exact chunk_size_loop_spec data stop 0#usize start start (le_refl _) (by scalar_tac) inside (by scalar_tac)
        (by simp)

theorem crlf_from_loop_spec (data : Slice U8) (index : Usize) (small : data.length + 4 ≤ Usize.max)
    (inside : index.val ≤ data.length) :
    crlf_from_loop data index ⦃ r => index.val ≤ r.val ∧ r.val ≤ data.length ⦄ := by
  suffices ∀ n (index : Usize), data.length - index.val = n → index.val ≤ data.length →
      crlf_from_loop data index ⦃ r => index.val ≤ r.val ∧ r.val ≤ data.length ⦄ from
    this _ index rfl inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure inside
    rw [crlf_from_loop.eq_def]
    step as ⟨next, hnext⟩
    split
    · step as ⟨b, _⟩
      split
      · step as ⟨c, _⟩
        split
        · simp only [WP.spec_ok]; scalar_tac
        · refine WP.spec_mono (ih _ (by scalar_tac) next rfl (by scalar_tac)) ?_
          intro r ⟨lo, hi⟩; exact ⟨by scalar_tac, hi⟩
      · refine WP.spec_mono (ih _ (by scalar_tac) next rfl (by scalar_tac)) ?_
        intro r ⟨lo, hi⟩; exact ⟨by scalar_tac, hi⟩
    · simp only [WP.spec_ok]; scalar_tac

@[step]
theorem crlf_from_spec (data : Slice U8) (index : Usize) (small : data.length + 4 ≤ Usize.max)
    (inside : index.val ≤ data.length) :
    crlf_from data index ⦃ r => index.val ≤ r.val ∧ r.val ≤ data.length ⦄ := by
  unfold crlf_from
  refine WP.spec_bind (crlf_from_loop_spec data index small inside) ?_
  intro r ⟨lo, hi⟩
  step as ⟨next, hnext⟩
  split
  · simp only [WP.spec_ok]; exact ⟨lo, hi⟩
  · simp only [WP.spec_ok]; exact ⟨by scalar_tac, le_refl _⟩

/-- **Chunked bodies.** A completed chunked body used no more bytes than
    were buffered and is at most `limit` bytes. -/
theorem decode_chunked_loop_spec (data : Slice U8) (limit : Usize)
    (small : data.length + 16 ^ 8 + 4 ≤ Usize.max) (bounded : limit.val + 16 ^ 8 ≤ Usize.max) :
    ∀ n (body : alloc.vec.Vec U8) (position : Usize), data.length - position.val = n →
      position.val ≤ data.length → body.length ≤ limit.val →
      decode_chunked_loop data limit body position ⦃ c =>
        ∀ b used, c = .Done b used → used.val ≤ data.length ∧ b.length ≤ limit.val ⦄ := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro body position measure inside fits
    rw [decode_chunked_loop.eq_def]
    step*
    all_goals try rfl
    all_goals scalar_tac

/-- A declared `Content-Length` the parser accepts is at most `limit`. -/
theorem framing_length {fields : Slice Field} {limit n : Usize}
    (h : framing fields limit = Result.ok (.Ok (.Length n))) : n.val ≤ limit.val := by
  unfold framing at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  repeat' (first | split at h | (obtain ⟨_, _, h⟩ := bind_ok_inv h))
  all_goals simp at h
  all_goals (subst h; scalar_tac)

theorem decode_chunked_spec (data : Slice U8) (start limit : Usize)
    (small : data.length + 16 ^ 8 + 4 ≤ Usize.max) (bounded : limit.val + 16 ^ 8 ≤ Usize.max)
    (inside : start.val ≤ data.length) :
    decode_chunked data start limit ⦃ c =>
      ∀ b used, c = .Done b used → used.val ≤ data.length ∧ b.length ≤ limit.val ⦄ := by
  unfold decode_chunked
  exact decode_chunked_loop_spec data limit small bounded _ _ start rfl inside
    (by simp [alloc.vec.Vec.new, alloc.vec.Vec.length])

/-- **The body.** A complete body used no more bytes than were buffered;
    a `Content-Length` body has the declared length and a chunked body is
    at most `limit`. -/
theorem body_of_spec (data : Slice U8) (start : Usize) (framed : Framing) (limit : Usize)
    (small : data.length + 16 ^ 8 + 4 ≤ Usize.max) (bounded : limit.val + 16 ^ 8 ≤ Usize.max)
    (inside : start.val ≤ data.length) (declared : ∀ n, framed = .Length n → n.val ≤ limit.val) :
    body_of data start framed limit ⦃ r => ∀ body used, r = .Ok (some (body, used)) →
      used.val ≤ data.length ∧ body.length ≤ limit.val ⦄ := by
  unfold body_of
  split
  · simp only [WP.spec_ok]
    intro body used h
    simp only [core.result.Result.Ok.injEq, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨hb, hu⟩ := h
    subst hb hu
    exact ⟨inside, by simp [alloc.vec.Vec.new, alloc.vec.Vec.length]⟩
  · rename_i length
    have bound := declared length rfl
    step*
    intro body used h
    cases h
    have same : v.length = s.length := by rw [s_post]; rfl
    exact ⟨by scalar_tac, by rw [same, s_post1]; scalar_tac⟩
  · refine WP.spec_bind (decode_chunked_spec data start limit small bounded inside) ?_
    intro c post
    split
    · simp only [WP.spec_ok]
      intro body used h
      simp only [core.result.Result.Ok.injEq, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨hb, hu⟩ := h
      subst hb hu
      exact post _ _ rfl
    · simp only [WP.spec_ok]; intro body used h; cases h
    · simp only [WP.spec_ok]; intro body used h; cases h

theorem body_of_ok {data : Slice U8} {start : Usize} {framed : Framing} {limit : Usize}
    {bytes : alloc.vec.Vec U8} {used : Usize}
    (h : body_of data start framed limit = Result.ok (.Ok (some (bytes, used))))
    (small : data.length + 16 ^ 8 + 4 ≤ Usize.max) (bounded : limit.val + 16 ^ 8 ≤ Usize.max)
    (inside : start.val ≤ data.length) (declared : ∀ n, framed = .Length n → n.val ≤ limit.val) :
    used.val ≤ data.length ∧ bytes.length ≤ limit.val := by
  obtain ⟨b, hb, post⟩ := returned_of_spec
    (body_of_spec data start framed limit small bounded inside declared)
  rw [hb] at h
  simp only [Result.ok.injEq] at h
  subst h
  exact post _ _ rfl

/-- **What an accepted request occupies.** When the strict parser returns a
    request, it used no more bytes than were buffered (so the native shell's
    `drain(..used)` cannot panic) and its body is at most `limit` bytes. The
    size premises hold for any buffer the native shell can hold (it bounds
    the buffer by `raw_limit`, about twice the request limit). -/
theorem parse_request_bounds {data host : Slice U8} {limit : Usize} {parsed : Parsed}
    (small : data.length + 16 ^ 8 + 4 ≤ Usize.max) (bounded : limit.val + 16 ^ 8 ≤ Usize.max)
    (h : parse_request data host limit = Result.ok (.Ok (some parsed))) :
    parsed.used.val ≤ data.length ∧ parsed.request.body.length ≤ limit.val := by
  unfold parse_request at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  repeat' (first | (obtain ⟨_, _, h⟩ := bind_ok_inv h) | split at h)
  -- Every refusal or incomplete branch contradicts `h`.
  all_goals try simp at h
  -- One path returns a request; name its pieces.
  all_goals
    have ends := head_end_some (by omega) ‹head_end data = Result.ok (some _)›
    have framed := ‹framing _ limit = Result.ok (.Ok _)›
    have start := add_eq ‹_ + 4#usize = Result.ok _›
    simp only [show ((4#usize : Usize) : Nat) = 4 from rfl] at start
    revert h
    generalize ‹body_of data _ _ limit = Result.ok (.Ok (some _))› = body
    revert body
    generalize ‹alloc.vec.Vec U8 × Usize› = found
    obtain ⟨bytes, used⟩ := found
    intro body h
    obtain ⟨u_le, b_le⟩ := body_of_ok body small bounded (by omega)
      (fun n hn => by rw [hn] at framed; exact framing_length framed)
    have e := Result.ok_injective h
    simp only [core.result.Result.Ok.injEq, Option.some.injEq] at e
    subst e
    exact ⟨u_le, b_le⟩

end garrett_stateless_core.proxy_http.Proofs
