import Lake
open Lake DSL

-- The bootstrap script installs the exact release recorded in manifest.json.
require aeneas from "../.tools/aeneas/backends/lean"

package «aivm-secrets-proofs»

lean_lib Generated where
  srcDir := "generated"
  roots := #[`AivmSecretsPrimitives, `AivmSecretsGarrettCore]

@[default_target] lean_lib Proofs where
  roots := #[`Freshness, `Check, `GarrettFoundation, `Garrett, `GarrettSecrecy, `GarrettProfiles, `GarrettReadTransition, `GarrettReadInvocations, `GarrettEmission, `GarrettCoordination, `GarrettRetryKey, `GarrettRebinding, `GarrettHttpAuth, `GarrettHttpRequest, `GarrettHttpWireDecimal, `GarrettHttpWireHeaders, `GarrettHttpWireFormatting, `GarrettHttpWireValidation, `GarrettHttpWire, `GarrettLineFrame, `GarrettCoordinatorAuthority, `GarrettCoordinatorReply, `GarrettApproval, `GarrettProtocol, `GarrettHistory, `GarrettEnrollment, `GarrettAuthority, `GarrettTrust, `GarrettOAuth, `GarrettLogin, `GarrettManifest, `GarrettDisclosure, `GarrettReflection, `GarrettJsonReflection, `GarrettClientMaterial, `GarrettBundle, `GarrettCheck]
