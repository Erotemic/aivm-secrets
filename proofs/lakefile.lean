import Lake
open Lake DSL

-- The bootstrap script installs the exact release recorded in manifest.json.
require aeneas from "../.tools/aeneas/backends/lean"

package «aivm-secrets-proofs»

lean_lib Generated where
  srcDir := "generated"
  roots := #[`AivmSecretsPrimitives, `AivmSecretsGarrettCore]

@[default_target] lean_lib Proofs where
  roots := #[`Freshness, `Check, `Garrett, `GarrettSecrecy, `GarrettProtocol, `GarrettHistory, `GarrettCheck]
