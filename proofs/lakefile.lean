import Lake
open Lake DSL

-- The bootstrap script installs the exact release recorded in manifest.json.
require aeneas from "../.tools/aeneas/backends/lean"

package «aivm-secrets-proofs»

lean_lib Generated where
  srcDir := "generated"
  roots := #[`AivmSecretsPrimitives, `AivmSecretsGarrettCore]

@[default_target] lean_lib Proofs where
  roots := #[`Freshness, `GarrettFoundation, `Garrett, `GarrettSecrecy, `GarrettProfiles, `GarrettReadTransition, `GarrettReadInvocations, `GarrettProviderExchange, `GarrettRequestEffects, `GarrettRequestSimulation, `GarrettCompletion, `GarrettCompletionSimulation, `GarrettDispatch, `GarrettDispatchSimulation, `GarrettRequestAdapter, `GarrettCurrentAdmission, `GarrettDispatchTrace, `GarrettCompletionTrace, `GarrettOwnedRequestTrace, `GarrettRequestContext, `GarrettProviderIO, `GarrettProviderChannel, `GarrettNativeWriterEvents, `GarrettNativeDispatchEvents, `GarrettProviderWire, `GarrettJsonStringScalar, `GarrettJsonString, `GarrettJsonWire, `GarrettJsonFrame, `GarrettPublicError, `GarrettRequestPrefix, `GarrettRequestTrace, `GarrettConfinement, `GarrettNoninterference, `GarrettReadPaths, `GarrettReadPrefixes, `GarrettProviderSimulation, `GarrettEmission, `GarrettCoordination, `GarrettRetryKey, `GarrettRebinding, `GarrettHttpAuth, `GarrettHttpRequest, `GarrettHttpWireDecimal, `GarrettHttpWireHeaders, `GarrettHttpWireFormatting, `GarrettHttpWireValidation, `GarrettHttpWire, `GarrettLineFrame, `GarrettGuestFrame, `GarrettCoordinatorAuthority, `GarrettCoordinatorReply, `GarrettApproval, `GarrettProtocol, `GarrettHistory, `GarrettEnrollment, `GarrettAuthority, `GarrettTrust, `GarrettOAuth, `GarrettLogin, `GarrettManifest, `GarrettDisclosure, `GarrettReflection, `GarrettJsonReflection, `GarrettClientMaterial, `GarrettNativeReadBoundary, `GarrettNR23Request, `GarrettNR23Effects, `GarrettNR23Failures, `GarrettNR23Guest, `GarrettNR23Assurance, `GarrettNR23ExactSinks, `GarrettNR23WriterOrigin, `GarrettChannelWork, `GarrettNR23NativeRoute, `GarrettNR23GuestObservations, `GarrettNR23ProductionBoundary, `GarrettSelectedConversionInput, `GarrettNR4ProjectedRelease, `GarrettNR4ErrorFrames, `GarrettNR4PairedNative, `GarrettNR4AdaptiveWire, `GarrettNR4Assurance, `GarrettProductionAuditRecord, `GarrettProductionSelectedRelease, `GarrettNR4ManifestRelease, `GarrettNR4AdaptiveRelease, `GarrettNR4ExchangeAdaptive, `GarrettNR4RequestAdaptive, `GarrettNR4FrameAdaptive, `GarrettProxyHttp, `GarrettProxyResponse, `GarrettWriteGate, `GarrettProductionReadFrame, `GarrettProductionResponseGate, `GarrettProductionAdapterRefinement, `GarrettProductionAssurance, `GarrettBundle]
