import Lake
open Lake DSL

-- `verification/toolchain.py bootstrap` installs the exact Aeneas release.
require aeneas from "../.tools/aeneas/backends/lean"

package «garrett-stateless-proofs»

lean_lib Generated where
  srcDir := "generated"
  roots := #[`GarrettStatelessCore]

@[default_target] lean_lib Proofs where
  roots := #[`GarrettBase64, `GarrettFoundation, `GarrettHttpAuth, `GarrettHttpWireDecimal, `GarrettHttpWireHeaders, `GarrettLogin, `GarrettProxyController, `GarrettProxyHttp, `GarrettProxyParse, `GarrettProxyResponse, `GarrettProxyTunnel, `GarrettReflection, `GarrettStateless, `GarrettStatelessBoundary, `GarrettStatelessCodec, `GarrettStatelessComposition, `GarrettStatelessConnection, `GarrettStatelessGrammar, `GarrettStatelessLogin, `GarrettStatelessMailbox, `GarrettStatelessProtocol, `GarrettStatelessProxy, `GarrettStatelessRoundTrip, `GarrettStatelessState, `GarrettStatelessStrict, `GarrettStatelessToken, `GarrettStatelessWitness]
