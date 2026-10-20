import GarrettProviderExchange
import GarrettConfinement

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-!
Conditional forward simulation of the actual extracted provider driver.
The four local primitive contracts below are EXTERNAL obligations for the
native TLS/clock/Write/parser boundary. They concern the projected credentialed
provider trace, not every native sink. No contract states the controller's
whole-run conclusion. In particular a failed send appends the same attempted
provider event as a successful send. Nothing uses provider arrival as a fact.
-/
namespace aivm_secrets_garrett_core.provider_exchange.Simulation

open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.provider_exchange.Proofs

structure Context where
  claims : credential_use.UseClaims
  grant : credential_use.UseGrant
  requested : alloc.vec.Vec U8
  selected : alloc.vec.Vec U8
  write : Bool
  allowed : Bool

/-- The operation/identity/destination binding held fixed within one driver.
    Grant activity and sampled clock values may change at external checks. -/
structure Binding where
  claims : credential_use.UseClaims
  grantClaims : credential_use.UseClaims
  operation : alloc.vec.Vec U8
  route : credential_use.Route
  requested : alloc.vec.Vec U8
  selected : alloc.vec.Vec U8
  write : Bool
  allowed : Bool

def Context.binding (ctx : Context) : Binding :=
  ⟨ctx.claims, ctx.grant.claims, ctx.grant.operation, ctx.grant.route,
    ctx.requested, ctx.selected, ctx.write, ctx.allowed⟩

def snapshot (ctx : Context) (stamp : manifest.AdmissionStamp) : Gate :=
  ⟨ctx.claims, ctx.grant, ctx.requested, ctx.selected, ctx.write, ctx.allowed,
    stamp.now, stamp.elapsed⟩

/-- Origin is equality to the actual source-owned admission-stamp constructor,
    rather than an unconstrained accepted/audit/provider-reached Boolean. -/
def Issued (ctx : Context) (stamp : manifest.AdmissionStamp) : Prop :=
  manifest.current ctx.claims ctx.grant ctx.requested ctx.selected ctx.write ctx.allowed
    stamp.now stamp.elapsed = Result.ok (.Ok stamp)

theorem issued_snapshot_is_accepted (ctx : Context) (stamp : manifest.AdmissionStamp)
    (issued : Issued ctx stamp) : (snapshot ctx stamp).accepted := by
  exact (manifest.StampProofs.current_success_iff ctx.claims ctx.grant ctx.requested ctx.selected
    ctx.write ctx.allowed stamp.now stamp.elapsed stamp).mp issued |>.1

def eventPhase : read_transition.Phase → Phase
  | .Preflight => .preflight
  | .Final => .final

def attemptedEvent (phase : read_transition.Phase) (ctx : Context)
    (stamp : manifest.AdmissionStamp) : Event :=
  .providerSend (eventPhase phase) (snapshot ctx stamp) true

/-- Explicit local hypotheses to instantiate at the native adapter. `observe`
    models the provider-attempt projection. The native SendState now supplies
    the concrete checked/attempted receipt; linking its mark to the private
    Write primitive and excluding other effects are separate contracts.
    Native source review and finite tests support, but do not prove, these
    primitive contracts or absence of other transitive effects. -/
structure Contracts {P C O X : Type} (ops : Provider P C O X)
    (view : P → Context) (observe : P → List Event) (ready : P → manifest.AdmissionStamp → Prop)
    (phase : read_transition.Phase) : Prop where
  issued : ∀ pending stamp, ready pending stamp → Issued (view pending) stamp
  setup : ∀ pending out after, ops.setup pending = Result.ok (out, after) →
    observe after = observe pending ∧ (view after).binding = (view pending).binding
  current : ∀ pending out after, ops.recheck pending = Result.ok (out, after) →
    observe after = observe pending ∧ (view after).binding = (view pending).binding ∧
      ∀ stamp, out = .Ok stamp → ready after stamp
  send : ∀ pending channel out after nextChannel stamp,
    ready pending stamp →
    ops.send pending channel = Result.ok (out, after, nextChannel) →
      observe after = observe pending ++ [attemptedEvent phase (view pending) stamp] ∧
        (view after).binding = (view pending).binding
  receive : ∀ pending channel out after, ops.receive pending channel = Result.ok (out, after) →
    observe after = observe pending ∧ (view after).binding = (view pending).binding

/-- Relates the returned production report to the actual primitive effects.
    The stamp and context at the checked boundary are retained as witnesses.
    Failed sends and failed responses both have a provider-attempt event. -/
def RelatedTrace {P O X : Type} (view : P → Context) (phase : read_transition.Phase)
    (report : Report O X) (events : List Event) : Prop :=
  match report.stage with
  | .Setup | .Admission => events = []
  | .Send | .Response | .Complete =>
    ∃ checked stamp, report.current = some stamp ∧ Issued (view checked) stamp ∧
      events = [attemptedEvent phase (view checked) stamp]

theorem related_trace_is_sound {P O X : Type} (view : P → Context)
    (phase : read_transition.Phase) (report : Report O X) (events : List Event)
    (related : RelatedTrace view phase report events) : SoundTrace events := by
  cases stage : report.stage <;> simp only [RelatedTrace, stage] at related
  · subst events; intro event member; simp at member
  · subst events; intro event member; simp at member
  all_goals
    obtain ⟨checked, stamp, _, issued, rfl⟩ := related
    intro event member
    simp only [List.mem_singleton] at member
    subst event
    exact ⟨issued_snapshot_is_accepted (view checked) stamp issued, rfl⟩

theorem related_trace_counts_attempts {P O X : Type} (view : P → Context)
    (phase : read_transition.Phase) (report : Report O X) (events : List Event)
    (related : RelatedTrace view phase report events) :
    Stage.attempted report.stage = Result.ok (events.length == 1) := by
  cases stage : report.stage <;> simp only [RelatedTrace, stage] at related
  · subst events; simp [Stage.attempted]
  · subst events; simp [Stage.attempted]
  all_goals
    obtain ⟨_, _, _, _, rfl⟩ := related
    simp [Stage.attempted]

/-- Forward simulation for ALL returned read runs of the source-owned driver,
    including early denial, audited-but-unsent and post-send failures. It
    composes local primitive contracts, preserving the binding and exact
    observed extension; the callback contracts remain external obligations. -/
theorem read_driver_forward_simulation {P C O X : Type} (ops : Provider P C O X)
    (view : P → Context) (observe : P → List Event) (phase : read_transition.Phase)
    (ready : P → manifest.AdmissionStamp → Prop)
    (contracts : Contracts ops view observe ready phase) (pending after : P) (report : Report O X)
    (returned : exchange ops pending ⟨phase, false⟩ = Result.ok (report, after)) :
    ∃ events, observe after = observe pending ++ events ∧
      RelatedTrace view phase report events ∧ (view after).binding = (view pending).binding := by
  cases (read_run_iff ops pending phase report after).mp returned with
  | setupDenied after error setup =>
    obtain ⟨observed, bound⟩ := contracts.setup _ _ _ setup
    exact ⟨[], by simpa using observed, rfl, bound⟩
  | admissionDenied channel s1 after error setup checked =>
    obtain ⟨a, ab⟩ := contracts.setup _ _ _ setup
    obtain ⟨b, bb, _⟩ := contracts.current _ _ _ checked
    exact ⟨[], by simpa [a] using b, rfl, bb.trans ab⟩
  | sendDenied channel nextChannel stamp s1 s2 after error setup checked sent =>
    obtain ⟨a, ab⟩ := contracts.setup _ _ _ setup
    obtain ⟨b, bb, stamped⟩ := contracts.current _ _ _ checked
    have checkedReady := stamped stamp rfl
    have issued := contracts.issued _ _ checkedReady
    obtain ⟨c, cb⟩ := contracts.send _ _ _ _ _ stamp checkedReady sent
    exact ⟨_, by simpa [a, b] using c, ⟨s2, stamp, rfl, issued, rfl⟩, cb.trans (bb.trans ab)⟩
  | responseDenied channel nextChannel stamp s1 s2 s3 after error setup checked sent received =>
    obtain ⟨a, ab⟩ := contracts.setup _ _ _ setup
    obtain ⟨b, bb, stamped⟩ := contracts.current _ _ _ checked
    have checkedReady := stamped stamp rfl
    have issued := contracts.issued _ _ checkedReady
    obtain ⟨c, cb⟩ := contracts.send _ _ _ _ _ stamp checkedReady sent
    obtain ⟨d, db⟩ := contracts.receive _ _ _ _ received
    exact ⟨_, by simpa [a, b, c] using d, ⟨s2, stamp, rfl, issued, rfl⟩, db.trans (cb.trans (bb.trans ab))⟩
  | complete channel nextChannel stamp s1 s2 s3 after value setup checked sent received =>
    obtain ⟨a, ab⟩ := contracts.setup _ _ _ setup
    obtain ⟨b, bb, stamped⟩ := contracts.current _ _ _ checked
    have checkedReady := stamped stamp rfl
    have issued := contracts.issued _ _ checkedReady
    obtain ⟨c, cb⟩ := contracts.send _ _ _ _ _ stamp checkedReady sent
    obtain ⟨d, db⟩ := contracts.receive _ _ _ _ received
    exact ⟨_, by simpa [a, b, c] using d, ⟨s2, stamp, rfl, issued, rfl⟩, db.trans (cb.trans (bb.trans ab))⟩

/-- The pre-existing acknowledged-audit prefix is carried into the new phase.
    Soundness of that prefix and the actual audit acknowledgement are supplied
    separately; this driver never manufactures an audit acknowledgement. -/
theorem extends_sound_observed_prefix {P C O X : Type} (ops : Provider P C O X)
    (view : P → Context) (observe : P → List Event) (phase : read_transition.Phase)
    (ready : P → manifest.AdmissionStamp → Prop)
    (contracts : Contracts ops view observe ready phase) (pending after : P) (report : Report O X)
    (before : SoundTrace (observe pending))
    (returned : exchange ops pending ⟨phase, false⟩ = Result.ok (report, after)) :
    SoundTrace (observe after) := by
  obtain ⟨events, extension, related, _⟩ := read_driver_forward_simulation
    ops view observe phase ready contracts pending after report returned
  rw [extension]
  intro event member
  rcases List.mem_append.mp member with prior | step
  · exact before event prior
  · exact related_trace_is_sound view phase report events related event step


/-- Concrete observation of the source-owned state used by the native guarded
    writer. It records an attempt, not successful arrival or response. -/
def recordedEvents (phase : read_transition.Phase) (ctx : Context) (state : SendState) : List Event :=
  match state.progress with
  | .Attempted stamp => [attemptedEvent phase ctx stamp]
  | _ => []

/-- The actual extracted begin_send produces precisely one marked attempt
    from a checked state. The native private Write call is after this gate;
    its OS/TLS semantics and all non-returning prefixes remain external. -/
theorem checked_send_state_records_one_attempt (phase : read_transition.Phase) (ctx : Context)
    (stamp : manifest.AdmissionStamp) (after : SendState)
    (issued : Issued ctx stamp)
    (sent : SendState.begin_send ⟨.Checked stamp⟩ false = Result.ok (true, after)) :
    recordedEvents phase ctx after = [attemptedEvent phase ctx stamp] ∧
      SoundTrace (recordedEvents phase ctx after) := by
  have same : after = ⟨.Attempted stamp⟩ := by
    simpa [SendState.begin_send, eq_comm] using sent
  subst after
  constructor
  · rfl
  · intro event member
    simp only [recordedEvents, List.mem_singleton] at member
    subst event
    exact ⟨issued_snapshot_is_accepted ctx stamp issued, rfl⟩

/-- Rejected repeated sends preserve the first receipt, so a failed write
    cannot re-arm a second native submission through this state. -/
theorem repeated_send_preserves_record (phase : read_transition.Phase) (ctx : Context)
    (stamp : manifest.AdmissionStamp) (write : Bool) (after : SendState)
    (sent : SendState.begin_send ⟨.Attempted stamp⟩ write = Result.ok (false, after)) :
    recordedEvents phase ctx after = [attemptedEvent phase ctx stamp] := by
  have same : after = ⟨.Attempted stamp⟩ := by
    simpa [SendState.begin_send, eq_comm] using sent
  subst after
  rfl

/-- Relate the actual source-owned prepare/acknowledge permit to the driver's
    phase. The native fsync acknowledgement that precedes acknowledge remains
    the explicit audit-primitive contract, not a manufactured providerReached bit. -/
theorem audited_read_driver_simulation {P C O X : Type} (ops : Provider P C O X)
    (view : P → Context) (observe : P → List Event) (phase : read_transition.Phase)
    (ready : P → manifest.AdmissionStamp → Prop)
    (contracts : Contracts ops view observe ready phase) (pending after : P) (report : Report O X)
    (prepared : read_transition.Prepared) (audited : read_transition.Audited)
    (prepare : read_transition.prepare phase false false = Result.ok (.Ok prepared))
    (ack : read_transition.acknowledge prepared true = Result.ok (.Ok audited))
    (returned : exchange ops pending audited = Result.ok (report, after)) :
    ∃ events, observe after = observe pending ++ events ∧
      RelatedTrace view phase report events ∧ (view after).binding = (view pending).binding := by
  have preservation := read_transition.Proofs.prepared_to_audited_preservation
    phase false false true prepared audited prepare ack
  have same : audited = ⟨phase, false⟩ := by
    cases audited with
    | mk actualPhase actualWrite =>
      simp only at preservation
      rcases preservation with ⟨rfl, rfl, _, _⟩
      rfl
  subst audited
  exact read_driver_forward_simulation ops view observe phase ready contracts pending after report returned

end aivm_secrets_garrett_core.provider_exchange.Simulation
