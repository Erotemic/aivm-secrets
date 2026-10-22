import GarrettNR4PairedNative

open Aeneas Aeneas.Std
set_option maxHeartbeats 7000000

/-!
NR-4 genuinely adaptive *native byte/history* noninterference. This is not
only the W5 abstract `GuestMessage` model. An adversary chooses each next
request from the complete previous public byte/outcome/metadata history; two
underlying states and state-transition implementations may differ.

The local step certificate has distinct, reviewable parts: W5 approval and
projection declassification, native frame conversion to a deterministic public
encoding, equality of callback/error outcomes, and preservation of the
private-state relation. The theorem derives native observation equality from
those parts rather than assuming the conclusion itself.

TLS framing, partial delivery, timing, connection closure and diagnostics must
be included in `metadata` or disclosed separately in a production refinement.
-/
namespace aivm_secrets_garrett_core.nr4.AdaptiveWire

open aivm_secrets_garrett_core.confinement.W5

/-- A public view richer than W5's abstract view. `wire` describes EXACT
    bytes offered to the reviewed guest writer, not proven network delivery.
    `outcomeCode` is the externally classified write result (including
    denial/error categories). `modeled` contains W5 status/length/close and
    permitted message disclosures; real environments may expose more. -/
structure NativeObservation where
  wire : List U8
  outcomeCode : Nat
  modeled : ObservedStep

/-- One candidate native/model adapter result. The `RequestCase` records the
    W5 path and its explicit declassification fields. -/
structure NativeStep where
  sourceCase : RequestCase
  offeredWire : List U8
  outcomeCode : Nat

noncomputable def observeNative (step : NativeStep) : NativeObservation :=
  { wire := step.offeredWire,
    outcomeCode := step.outcomeCode,
    modeled := observed step.sourceCase }

/-- A precise JSON/frame conversion obligation: the native sender offers the
    deterministic encoding of *only* the approved W5 messages. Proofs about
    successful and sanitized denial frames in the other NR-4 modules can
    discharge it for individual returned cases. It is not yet a theorem for
    every Rust `Bridge::answer` branch. -/
def EncodesDeclassification
    (encodePublic : List GuestMessage → List U8)
    (step : NativeStep) : Prop :=
  step.offeredWire = encodePublic (observed step.sourceCase).messages

/-- If both native steps refine the same deterministic encoding of their W5
    observations, and if their declassified W5 decisions and public outcome
    codes agree, then the actual offered bytes AND complete modeled
    observations are equal. This does not postulate offered-byte equality. -/
theorem declassified_steps_have_equal_native_observation
    (encodePublic : List GuestMessage → List U8)
    (left right : NativeStep)
    (declassified : DeclassificationAgreement
      left.sourceCase right.sourceCase)
    (encodesLeft : EncodesDeclassification encodePublic left)
    (encodesRight : EncodesDeclassification encodePublic right)
    (outcomes : left.outcomeCode = right.outcomeCode) :
    observeNative left = observeNative right := by
  have eqModel := request_noninterference
    left.sourceCase right.sourceCase declassified
  unfold EncodesDeclassification at encodesLeft encodesRight
  unfold observeNative
  rw [encodesLeft, encodesRight, eqModel, outcomes]

/-- Successful or denied requests still have an observable outcome code,
    including a distinction between a failed write and a returned write.
    Confidentiality must not discard this component. -/
theorem different_native_outcome_code_is_visible
    (bytes : List U8) (left right : Nat) (model : ObservedStep)
    (different : left ≠ right) :
    NativeObservation.mk bytes left model ≠
      NativeObservation.mk bytes right model := by
  intro equal
  exact different (congrArg NativeObservation.outcomeCode equal)

/-- Even if modeled messages and outcome codes are equal, differing offered
    bytes are visible in the stated observation relation. -/
theorem different_offered_bytes_are_visible
    (left right : List U8) (code : Nat) (model : ObservedStep)
    (different : left ≠ right) :
    NativeObservation.mk left code model ≠
      NativeObservation.mk right code model := by
  intro equal
  exact different (congrArg NativeObservation.wire equal)

/-- Status/close/pagination metadata differences are likewise observable;
    the W5 proof itself explicitly allows them only under declassification. -/
theorem different_public_metadata_is_visible
    (wire : List U8) (code : Nat) (messages : List GuestMessage)
    (left right : WireMetadata) (different : left ≠ right) :
    NativeObservation.mk wire code (ObservedStep.mk messages left) ≠
      NativeObservation.mk wire code (ObservedStep.mk messages right) := by
  intro equal
  have sameModel : ObservedStep.mk messages left =
      ObservedStep.mk messages right :=
    congrArg NativeObservation.modeled equal
  exact different (congrArg ObservedStep.metadata sameModel)

/-- Two independent execution semantics can use different internal state
    representations while sharing the adversary's public request strategy. -/
noncomputable def adaptiveNativeRun {State Request : Type}
    (strategy : List NativeObservation → Nat → Request)
    (step : State → Request → NativeStep × State) :
    Nat → State → List NativeObservation → List NativeObservation
  | 0, _, history => history
  | n + 1, state, history =>
      let result := step state (strategy history n)
      adaptiveNativeRun strategy step n result.2
        (history ++ [observeNative result.1])

/-- The local NR-4 contract: declassification at the W5 source layer,
    source-to-native JSON/framing correspondence for each side, externally
    visible outcome agreement, and a relation for the next private states.
    None of these premises is the desired equality of complete observations.
    In particular, `encodesLeft` must be proved from the production converter,
    not asserted merely because `observeNative` is a convenient abstraction. -/
structure PairedStepCertificate
    {LeftState RightState Request : Type}
    (encodePublic : List GuestMessage → List U8)
    (stepLeft : LeftState → Request → NativeStep × LeftState)
    (stepRight : RightState → Request → NativeStep × RightState)
    (related : LeftState → RightState → Prop)
    (left : LeftState) (right : RightState) (request : Request) : Prop where
  declassified : DeclassificationAgreement
    (stepLeft left request).1.sourceCase
    (stepRight right request).1.sourceCase
  encodesLeft : EncodesDeclassification encodePublic
    (stepLeft left request).1
  encodesRight : EncodesDeclassification encodePublic
    (stepRight right request).1
  outcomes : (stepLeft left request).1.outcomeCode =
    (stepRight right request).1.outcomeCode
  continued : related (stepLeft left request).2 (stepRight right request).2

/-- One paired step certificate implies identical public native observation,
    including exact offered bytes, public outcome class and modeled metadata.
    This is derived, not an assumption of the certificate. -/
theorem certificate_produces_equal_public_step
    {LeftState RightState Request : Type}
    (encodePublic : List GuestMessage → List U8)
    (stepLeft : LeftState → Request → NativeStep × LeftState)
    (stepRight : RightState → Request → NativeStep × RightState)
    (related : LeftState → RightState → Prop)
    (left : LeftState) (right : RightState) (request : Request)
    (certificate : PairedStepCertificate
      encodePublic stepLeft stepRight related left right request) :
    observeNative (stepLeft left request).1 =
      observeNative (stepRight right request).1 := by
  exact declassified_steps_have_equal_native_observation
    encodePublic (stepLeft left request).1 (stepRight right request).1
    certificate.declassified certificate.encodesLeft
    certificate.encodesRight certificate.outcomes

/-- The main NR-4 multi-session theorem: for ANY finite number of requests,
    and ANY adversarial strategy which chooses each next request from all
    previously returned byte/outcome/metadata observations, the histories
    agree. The private states and transition implementations may differ.

    All the work lies in deriving `PairedStepCertificate` for actual native
    sessions; Lean does not infer these obligations from the observer's
    inability to inspect a credential. -/
theorem adaptive_native_noninterference
    {LeftState RightState Request : Type}
    (encodePublic : List GuestMessage → List U8)
    (strategy : List NativeObservation → Nat → Request)
    (stepLeft : LeftState → Request → NativeStep × LeftState)
    (stepRight : RightState → Request → NativeStep × RightState)
    (related : LeftState → RightState → Prop)
    (stepPreserves : ∀ left right request, related left right →
      PairedStepCertificate encodePublic stepLeft stepRight related
        left right request)
    (rounds : Nat) (left : LeftState) (right : RightState)
    (history : List NativeObservation) (initial : related left right) :
    adaptiveNativeRun strategy stepLeft rounds left history =
      adaptiveNativeRun strategy stepRight rounds right history := by
  induction rounds generalizing left right history with
  | zero => rfl
  | succ remaining ih =>
    let request := strategy history remaining
    have cert := stepPreserves left right request initial
    have sameStep := certificate_produces_equal_public_step
      encodePublic stepLeft stepRight related left right request cert
    have nextRelated := cert.continued
    change adaptiveNativeRun strategy stepLeft remaining
        (stepLeft left request).2
        (history ++ [observeNative (stepLeft left request).1]) =
      adaptiveNativeRun strategy stepRight remaining
        (stepRight right request).2
        (history ++ [observeNative (stepRight right request).1])
    rw [sameStep]
    exact ih (stepLeft left request).2 (stepRight right request).2
      (history ++ [observeNative (stepRight right request).1]) nextRelated

/-- The special case of a single request is also useful when validating a
    concrete adapter fixture before relying on an adaptive argument. -/
theorem one_step_native_noninterference
    {LeftState RightState Request : Type}
    (encodePublic : List GuestMessage → List U8)
    (stepLeft : LeftState → Request → NativeStep × LeftState)
    (stepRight : RightState → Request → NativeStep × RightState)
    (related : LeftState → RightState → Prop)
    (left : LeftState) (right : RightState) (request : Request)
    (cert : PairedStepCertificate
      encodePublic stepLeft stepRight related left right request) :
    observeNative (stepLeft left request).1 =
      observeNative (stepRight right request).1 := by
  exact certificate_produces_equal_public_step
    encodePublic stepLeft stepRight related left right request cert

end aivm_secrets_garrett_core.nr4.AdaptiveWire
