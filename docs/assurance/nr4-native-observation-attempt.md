# NR-4: Native guest observation and adaptive noninterference — large proof attempt

**Status (2026-10-22):** proposed five-module Lean proof batch; *compilation
must be established on the maintainer's pinned Lake/Lean toolchain*. The
previous `GarrettNR23ProductionBoundary` batch was reported to build
successfully. The new NR-4 batch is **not** a claim that the deployed broker
is formally confidential: important source-to-native and external I/O
contracts remain to be discharged.

## Goal and threat model

An untrusted client running in an AIVM guest should be unable to learn host
credential contents or unselected provider data through the broker's
approved **read-only** interface, except through explicitly selected
provider fields, public denial categories, approval/revocation outcomes, and
other declared metadata. An adaptive client may choose its next request
based on every previously visible response and error. The host operator
chooses the bounded manifest, credential, endpoint, output projection and
policy; a guest cannot expand that authority by changing its request.

This campaign defines an observation richer than W5's parsed
`GuestMessage`: **exact bytes offered to the reviewed native frame writer**,
**the publicly classified writer/error result**, and W5's modeled
`ObservedStep` containing approval/denial and metadata. The modeled metadata
currently carries status, length, pagination/more-data and close state.
The native contract must be refined to cover real EOF, TLS alerts, frame
segmentation/partial output, timing, logs or any other channels claimed to
be guest-visible. Equality of bytes **offered** to `write_all` is not proof
that two guests received exactly those bytes.

## Exact theorem and model map

| Module | Main theorem / property | Source linkage and material premise |
| --- | --- | --- |
| `GarrettNR4ProjectedRelease` | `selected_values_equal_of_recursive_agreement` | Existing extracted `disclosure.project` and `recursive_projection_noninterference`: two successful recursively agreeing projections select an equal value, rather than assuming equal output bytes. |
| `GarrettNR4ProjectedRelease` | `approved_conversion_yields_equal_byte_encoding` | Equal selected values are converted through a common operator-chosen function `encodeSelected`; the actual production `Completed::into_value`/`serde_json`/`json::capture` conversion must be shown to implement that function. |
| `GarrettNR4ProjectedRelease` | `successful_approved_projection_prepares_identical_guest_frames` and `...offers_identical_bytes_after_send` | Reuses the extracted `json_wire.prepare` and `guest_frame.Frame.send` contracts; derives the actual offered byte equality from projection agreement, including failure-returned frame attempts. |
| `GarrettNR4ErrorFrames` | `same_denial_class_prepares_equal_wire`, `...after_send` | A concrete six-class public error taxonomy mirrors `tls.rs::failure`. Distinct private errors in the *same class* have equal JSON/framed bytes under `SanitizesTo`. The Rust classifier/capture correspondence is not inferred. |
| `GarrettNR4ErrorFrames` | `native_error_frame_failure_is_single_attempt` | Reuses the source-extracted frame replay invariant; failed/partial writes consume the frame and do not authorize retransmission. It does not claim rollback of bytes already delivered. |
| `GarrettNR4PairedNative` | `native_success_has_accounted_authorized_send_history` | For each returned `read_transition.run_current`, reuses NR-2/3 source-derived audit/current-admission and exact **ordered** sink accounting, conditional on `NativeContext` and `ExactNativeSinkCoverage`. |
| `GarrettNR4PairedNative` | `paired_native_reads_have_independent_sound_traces_and_same_guest_bytes` | Combines two independent returned source runs, their own authorized/audited effect traces, and recursive projected-field agreement to obtain equal prepared guest wire bytes. No equality of internal host state, credential or raw provider response is postulated. |
| `GarrettNR4AdaptiveWire` | `declassified_steps_have_equal_native_observation` | A W5 `DeclassificationAgreement`, two one-step `EncodesDeclassification` contracts, and equal public outcome codes yield full equality of the defined native observations. Byte equality is derived from deterministic encoding of the W5 result. |
| `GarrettNR4AdaptiveWire` | `adaptive_native_noninterference` | Separate native state spaces and transition functions; any adversary choosing its next request from the full previous native observation history sees equal finite traces when each native step supplies the *decomposed* `PairedStepCertificate`. |
| `GarrettNR4Assurance` | `paired_returned_native_reads_have_sound_sends_and_public_equivalence` | Composes the actual returned-request/audit proof, ordered native sink-coverage, recursive selected-value agreement, exact prepared guest bytes, modeled public metadata and outcome-class equality. |
| `GarrettNR4Assurance` | `arbitrary_adaptive_guest_strategy_sees_equivalent_public_history` | Exports the adaptive result as a named assurance target for explicit native session implementation refinement. |

### Why this is stronger than NR-3

NR-3 could establish equal public frame bytes for two native runs when
*equality of encoded bytes* was given as a premise. Here the principal
successful-read proof **derives** that byte equality from the already
source-linked `disclosure.project` recursive agreement, via a *single named
selected-value conversion contract*. The two source runs independently
retain the NR-2/3 admission/audit/sink guarantees. The new adaptive theorem
is over full offered-byte/outcome/metadata histories, not just W5 parsed
messages; each next request is chosen from the entire public history.

However, the new theorem **does not** eliminate every native premise. A
`SelectedConversion` field is a real Rust-to-Lean contract. If the native
bridge sends a raw provider JSON, a debug string, or a second frame, that
contract may be false. The same applies to `EncodesDeclassification` in the
adaptive session certificate. The theorem does not automatically show the
Rust adapter satisfies those premises merely because its proof compiles.

## How the maintainer should read the proofs

1. Start with `selected_values_equal_of_recursive_agreement`. Its actual
   hypothesis is equality on the selected paths and decisions prescribed by
   `ProjectionAgreement`, **not equality of complete secret JSON**. Inspect
   `GarrettDisclosure.lean` and the actual path/type/limit rules.
2. Read `SelectedConversion`. It is the contract connecting the selected
   result to the native serializer. Look at the three call sites in
   `rust/crates/aivm-secrets-garrett/src/tls.rs`: `failure`, `GuestFrame::from_answer`
   and `Bridge::serve`. The contract is **not yet implemented as a proof of
   Rust `serde_json`/`json::capture`**.
3. Read `NativeSuccess` and `native_success_has_accounted_authorized_send_history`.
   The `coverage` field is the strong, **unproved** mapping from actual
   credential-bearing I/O to the source's ordered provider-send events. The
   theorem derives admission/audit correctness **if** that mapping is true.
4. Read the `PairedStepCertificate` in `GarrettNR4AdaptiveWire`. Verify that
   it does **not** take equality of public histories or native observation
   results as an assumption; it requires modeled declassification agreement,
   native frame-conversion correctness, classified outcome equality, and
   next-state preservation. The last point is a nontrivial future obligation.
5. Read the top-level `GarrettNR4Assurance` theorem and inspect each premise.
   In particular, `publicFirst = publicSecond` and W5 metadata agreement
   should *not* be assumed automatic for arbitrary private differences.
6. Check the native source-guard separately and understand its limitations:
   intact source anchors do not establish transitive execution correspondence.

## Important differences a malicious client CAN observe

- Allowed projection selects a bearer credential: the selected field itself
  is an intentional declassification. Reflection rejection may stop literal
  credentials, but the rejection decision can also be observable. A general
  theorem must model that decision, not assume it always agrees.
- A revoked identity is rejected while a current identity succeeds. The
  policy outcome is observable and declassified by the W5 agreement.
- A denied operation may produce `invalid_capability`, `invalid_request`,
  `denied`, `unsafe_file`, `outcome_unknown` or a generic error. Different
  public error classes are distinguishable. The theorem only guarantees
  equal framed bytes for the same public class.
- A failing guest writer might have already transmitted a prefix before
  returning an error. Equality of buffers **offered** to the writer does not
  force equal prefixes delivered over TLS. Retry prevention is proven only
  for the original spent frame; new channels or process restarts differ.
- Changed frame lengths, status codes, pagination flags, EOF or connection
  close states are observable. W5 explicitly requires agreement of those
  components; they are not inferred from recursive provider projection.
- Timing, TLS alerts, filesystem mounts, hypervisor escape, other host
  processes, audit log access, process diagnostic output, CPU caches and
  provider-side effects are not covered by this finite guest-framing theorem.

## Remaining non-circular obligations, ranked

**Blockers for unattended credential-bearing AIVM use:**

1. **Concrete selected conversion**: formally link `Completed::into_value`,
   `disclosure.project`, literal reflection checks, `Bridge::answer`,
   `tls::failure`, `serde_json::Value`, `json::capture`, `json_wire.prepare` and
   the actual native frame writer. The needed contract must expose success,
   error and length/close behavior, not just selected values.
2. **Real native sink closure**: prove the production credential-bearing
   sends, including rustls/TLS and all reachable native alternatives, match
   source events *one for one in order*. The current `ExactNativeSinkCoverage`
   is an obligation, not a proved property of production Rust.
3. **Per-step adaptive simulation**: connect each actual native session
   state/input/result to a W5 `RequestCase`, show declassification and full
   `EncodesDeclassification`/outcome/metadata contracts, and preserve the
   private-state relation across callbacks, revocation, errors and sequential
   sessions. This must be non-circular: no premise saying merely that the
   two native guest observations are equal.
4. **Guest observation closure**: identify and cover all guest-visible
   status, bytes, close, error, timing or other channels under the selected
   transport profile, or explicitly narrow the theorem to an allowed subset.
5. **Audit and OS contracts**: relate native append+`sync_all` to formal
   acknowledgement and socket writers to high-level attempt events. Keep
   crypto, hypervisor, OS, provider semantic and physical durability contracts
   explicit. Do not promote the formalized core to a whole-service proof.

The first three are application implementation obligations; adding them as
unqualified global assumptions would not establish the desired security of
`aivm-secrets`.

## Validation instructions

```bash
cd ~/code/aivm-secrets
python dev/verification/nr23_native_edges.py check
python dev/verification/nr4_observation_edges.py check
python -m pytest -q tests/test_nr23_native_edges.py tests/test_nr4_observation_edges.py
cd proofs
lake exe cache get
lake build GarrettNR4Assurance
cd ..
```

The `GarrettNR4Assurance` target imports the other four new modules and the
accepted NR-2/NR-3 graph. Compilation establishes its stated theorems under
their explicit hypotheses. It does not independently check Rust/TLS semantics.
The source-shape guard intentionally does not use a default hook or treat
formatting/anchor scans as an assurance gate.

At authoring time Lean/Lake was not present; the five-module build must be
checked on the pinned machine before this increment can be accepted. Fix
elaboration/type/proof issues in consolidated passes, never by adding axioms
or weakening theorem statements. Keep ordinary successful builds quiet; do
not add routine axiom-print or sorry/admit inventories. An opt-in transitive
axiom comparison belongs at final NR-5 review.

## Example falsifiers for the next source-linked increment

- Add a new native `Write` call to an unreviewed TLS/backend route. The
  previous request trace theorem still compiles, but `ExactNativeSinkCoverage`
  is false if that call emits a credential.
- Make `GuestFrame::from_answer` serialize an unselected raw provider field.
  W5 projection agreement and Lean `SelectedConversion` no longer describe
  the actual implementation.
- Make `failure(error)` include `format!("{error:?}")`. Two private errors
  in the same public class may produce different public bytes, falsifying
  `SanitizesTo`.
- Change a native error return path to send one extra frame or a TLS alert
  only for one secret value. The simplified guest writer may remain correct,
  but the full observation refinement fails.
- Change the selected provider outcome in a way which changes reflection
  rejection, timeout/EOF or public metadata. `DeclassificationAgreement` is
  not automatic and should fail or declare that observable difference.
- Send a partial provider write, then reconstruct a fresh channel and retry.
  The original spent-frame lemma does not prohibit new-channel retries; the
  source control, session and outcome-uncertainty model must address them.

**Review recommendation:** treat successful compilation as proof of the
scoped, conditional theorems only. Review the missing runtime premises and
build an independently checked Rust-to-Lean refinement before calling the
system safe for unattended credential-bearing guest agents.
