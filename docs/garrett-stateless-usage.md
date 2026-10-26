# Using `garrett-stateless-v1`: Python, Rust and the command line

Two independent implementations of one wire specification,
[`garrett-stateless-v1.md`](garrett-stateless-v1.md):

- **Python:** the `aivm_secrets.garrett_stateless` package of the `aivm-secrets`
  distribution. It requires only `cryptography`, and no AIVM, Rust, Lean, TPM
  or VM manager.
- **Rust:** the standalone crate `rust/crates/garrett-stateless` (library and
  binary). It depends only on the dependency-free core
  `aivm-secrets-garrett-core`, plus `ring`, `rustls`, `x509-parser`, `rcgen`
  and `webpki-roots`. The `tpm` feature adds the existing tpm2-tools signer
  from `aivm-secrets-garrett`.

Both implementations install a `garrett-stateless` command with the same
interface. Neither is published to a package registry yet.

## Install

```bash
pip install /path/to/aivm-secrets            # Python library + garrett-stateless command
cargo install --path rust/crates/garrett-stateless            # Rust binary
cargo install --path rust/crates/garrett-stateless --features tpm   # with TPM agent keys
```

In a Cargo project:

```toml
[dependencies]
garrett-stateless = { path = "/path/to/aivm-secrets/rust/crates/garrett-stateless" }
```

The crate builds outside the workspace on stable Rust (checked with 1.98).

## Deployment in five files

```bash
garrett-stateless pki ca --name "agents CA" --cert ca.pem --key ca.key        # development only
garrett-stateless pki server --ca-cert ca.pem --ca-key ca.key --name broker.example --name proxy.example \
    --cert server.pem --key server.key
garrett-stateless pki client --ca-cert ca.pem --ca-key ca.key --name agent-1 \
    --uri spiffe://example/agent-1 --cert agent.pem --key agent.key
garrett-stateless keys init --issuer https://broker.example --out broker-keys.json
garrett-stateless keys export --keys broker-keys.json --out proxy-keys.json    # no signing seed, no state key
```

Write `provider.json`, `broker.json` and `proxy.json` as in sections 11 and 12
of the specification. Register `<public_url>callback` as the OAuth redirect URI.
Then:

```bash
garrett-stateless broker --config broker.json      # prints {"agent":..,"browser":..,"role":"broker"}
garrett-stateless proxy  --config proxy.json       # prints {"address":..,"role":"proxy"}; run as many as you like
```

Agent side:

```bash
garrett-stateless agent login --broker https://broker.example:9443 --provider github \
    --ca ca.pem --cert agent.pem --key agent.key --out surrogate
# -> {"authorization_url": "...", "confirmation": "AB12-CD34", ...}; a human opens the URL
garrett-stateless inspect --token-file surrogate               # unverified public claims
garrett-stateless agent request --proxy https://proxy.example:8443 \
    --ca ca.pem --cert agent.pem --key agent.key --token-file surrogate /user
curl --cacert ca.pem --cert agent.pem --key agent.key \
    -H "Authorization: Bearer $(cat surrogate)" https://proxy.example:8443/user    # any HTTP client
garrett-stateless agent renew --broker https://broker.example:9443 \
    --ca ca.pem --cert agent.pem --key agent.key --token-file surrogate --out surrogate.new
```

Operator issuance for a credential you already hold (an API key, or a test
token) uses no OAuth:

```bash
garrett-stateless mint --config broker.json --provider api --credential-file key.txt \
    --certificate agent.pem --out surrogate
```

Key rotation, and revocation by retiring a key:

```bash
garrett-stateless keys rotate --keys broker-keys.json --kid k2
garrett-stateless keys export --keys broker-keys.json --out proxy-keys.json   # deploy to all proxies first
# ... restart the broker; later:
garrett-stateless keys retire --keys broker-keys.json --kid k1                 # export and deploy again
```

## Python API

```python
from pathlib import Path
from aivm_secrets.garrett_stateless import Agent, Broker, Endpoint, Proxy, inspect

broker = Broker.from_file(Path('broker.json'))           # or Broker(config, keys, endpoint=..., clock=...)
running = broker.serve()                                  # RunningBroker: .agent_address, .browser_address, .stop()
proxy = Proxy.from_file(Path('proxy.json')).serve()       # RunningProxy: .address, .stop()

agent = Agent(Path('ca.pem'), Path('agent.pem'), Path('agent.key'))
endpoint = Endpoint.parse('https://broker.example:9443', running.agent_address)
started = agent.begin_login(endpoint, 'github', 'read:user')   # LoginStarted
surrogate = agent.wait_for_token(endpoint, started.login, timeout=600)   # IssuedToken
header, payload = inspect(surrogate.token)                # unverified, for display
response = agent.request(Endpoint.parse('https://proxy.example:8443', proxy.address),
                         surrogate.token, 'GET', '/user')
```

Lower-level pieces:

| Module | Use |
| --- | --- |
| `decisions` | The decision functions (`admit`, `open_surrogate`, `issue`, `renew`, `begin_login`, `accept_callback`, `deliver`, `serve`), mirrored from the extracted Rust |
| `token` | `Sealer`, `Opener`, `ClaimCopy`, `copy_upstream`, `inspect` |
| `keys` | `BrokerKeys` (`generate`, `rotate`, `retire`, `export_proxy`), `ProxyKeys` |
| `config` | `BrokerConfig`, `ProxyConfig`, `ProviderConfig` |
| `broker` | `Broker`, `TokenEndpoint` (plug in another token exchange), `HttpsTokenEndpoint`, `mint_with` |
| `login` | Sealed state, PKCE, the transient `Mailbox` |
| `tls` | Server and client contexts, `PeerIdentity` |
| `pki` | Development CA and certificates |

Errors are typed: `Rejection` (surrogate refused or not issued, `.code`),
`ProtocolError` (broker or proxy exchange, `.code`), `ConfigError`,
`KeyFileError`. No public return value contains a provider credential, except
`Opener.unseal` and `decisions.open_surrogate`. Those are the proxy-side
privileged calls.

## Rust API

```rust
use garrett_stateless::{agent::{Agent, Endpoint}, broker::Broker, proxy::Proxy, tls::ClientIdentity};
use std::sync::Arc;

let broker = Arc::new(Broker::from_file("broker.json".as_ref())?).serve()?;   // RunningBroker
let proxy = Arc::new(Proxy::from_file("proxy.json".as_ref())?).serve()?;      // RunningProxy

let agent = Agent::new(&ca_pem, ClientIdentity::Software { certificate, key })?;
let started = agent.begin_login(&Endpoint::parse("https://broker.example:9443", None)?, "github", None)?;
let surrogate = agent.wait_for_token(&broker_endpoint, &started.login, std::time::Duration::from_secs(600))?;
let response = agent.request(&proxy_endpoint, &surrogate.token, "GET", "/user", &[], b"")?;
```

Extension points:

- `broker::TokenEndpoint`: replace the HTTPS code exchange.
- `stateless::SurrogateSealer` and `SurrogateOpener` (core traits): alternative
  key custody, such as an HSM.
- `tls::ClientIdentity::Resolver`: any `rustls` client-certificate resolver,
  for example a TPM or HSM. With feature `tpm`, `ClientIdentity::tpm(configuration,
  certificate)` uses the tpm2-tools signer.

The decisions themselves are the core functions `stateless::{open, issue,
renew}`, `stateless_login::*` and `stateless_proxy::serve`. They are the ones
the Lean theorems are about.

## TPM agent keys

```json
{"tcti": "device:/dev/tpmrm0", "persistent_handle": 2164260881,
 "authorization_file": "/path/auth", "public_area_file": "/path/key.tpmt", "work_directory": "/path/work"}
```

```bash
garrett-stateless agent request --tpm tpm.json --cert agent.pem --ca ca.pem --proxy ... --token-file surrogate /user
```

The CA must certify the TPM key's public part only after checking its
provenance. This profile does not check attestation at use time; see section
6.1 of the specification for the five distinct guarantees. The Python agent
supports software keys only, and refuses `--tpm` rather than falling back to a
software key. The optional test `tests/test_garrett_stateless_tpm.py` runs a
TPM-bound login and request on a disposable swtpm.

## Tests

```bash
python -m pytest -q tests/test_garrett_stateless*.py      # Python, vectors, interop (needs the Rust build), TPM (optional)
cargo test -p garrett-stateless -p aivm-secrets-garrett-core   # Rust unit, vectors and end-to-end
bash scripts/garrett-stateless-demo.sh                    # container walkthrough
```
