import Lake
open Lake DSL

-- The bootstrap script installs the exact release recorded in manifest.json.
require aeneas from "../.tools/aeneas/backends/lean"

package «aivm-secrets-proofs»

lean_lib Generated where
  srcDir := "generated"
  roots := #[`AivmSecretsPrimitives, `AivmSecretsGarrettCore]

@[default_target] lean_lib Proofs where
  roots := #[`Freshness, `GarrettFoundation, `Garrett, `GarrettSecrecy, `GarrettProfiles, `GarrettReadTransition, `GarrettReadInvocations, `GarrettProviderExchange, `GarrettRequestEffects, `GarrettRequestSimulation, `GarrettCompletion, `GarrettCompletionSimulation, `GarrettDispatch, `GarrettDispatchSimulation, `GarrettRequestAdapter, `GarrettCurrentAdmission, `GarrettDispatchTrace, `GarrettCompletionTrace, `GarrettOwnedRequestTrace, `GarrettRequestContext, `GarrettProviderIO, `GarrettProviderChannel, `GarrettNativeWriterEvents, `GarrettProviderWire, `GarrettJsonStringScalar, `GarrettJsonString, `GarrettJsonWire, `GarrettJsonFrame, `GarrettRequestPrefix, `GarrettRequestTrace, `GarrettConfinement, `GarrettProviderSimulation, `GarrettEmission, `GarrettCoordination, `GarrettRetryKey, `GarrettRebinding, `GarrettHttpAuth, `GarrettHttpRequest, `GarrettHttpWireDecimal, `GarrettHttpWireHeaders, `GarrettHttpWireFormatting, `GarrettHttpWireValidation, `GarrettHttpWire, `GarrettLineFrame, `GarrettGuestFrame, `GarrettCoordinatorAuthority, `GarrettCoordinatorReply, `GarrettApproval, `GarrettProtocol, `GarrettHistory, `GarrettEnrollment, `GarrettAuthority, `GarrettTrust, `GarrettOAuth, `GarrettLogin, `GarrettManifest, `GarrettDisclosure, `GarrettReflection, `GarrettJsonReflection, `GarrettClientMaterial, `GarrettBundle]
