# garrett-stateless

A standalone Rust implementation of **`garrett-stateless-v1`**, the
credential-brokering architecture Matthew Garrett described in
[*Securing agentic identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/):

- an untrusted agent authenticates to a **broker** with a client certificate
  (mTLS) and asks for access to a provider;
- a human approves in a browser; the provider redirects to the broker, which
  exchanges the code (PKCE) and mints a **surrogate JWT**: signed by the
  broker, carrying the real provider token AES-256-GCM-encrypted, and bound to
  the agent's certificate (`cnf.x5t#S256`);
- the agent sends ordinary API requests with the surrogate as its bearer
  token to a **stateless mTLS proxy**, which checks the binding against the
  connection's certificate, decrypts the real token, substitutes it and
  forwards to the provider route the token names.

Neither broker nor proxy persists anything; the proxy keeps no state at all,
so any number of replicas with the same keys accept the same surrogates.
The normative specification, including every divergence from the article,
is [`docs/garrett-stateless-v1.md`](../../docs/garrett-stateless-v1.md).

**Experimental and unaudited.** Not published to crates.io.

## Use as a library

```toml
[dependencies]
garrett-stateless = { git = "<this repository>", package = "garrett-stateless" }
# or, from a checkout:
garrett-stateless = { path = "crates/garrett-stateless" }
```

```rust
use garrett_stateless::{agent::{Agent, Endpoint}, tls::ClientIdentity};

let agent = Agent::new(&ca_pem, ClientIdentity::Software { certificate, key })?;
let broker = Endpoint::parse("https://broker.example:9443", None)?;
let login = agent.begin_login(&broker, "github", Some("read:user"))?;
println!("open {} (code {})", login.authorization_url, login.confirmation);
let surrogate = agent.wait_for_token(&broker, &login.login, std::time::Duration::from_secs(600))?;

let proxy = Endpoint::parse("https://proxy.example:8443", None)?;
let response = agent.request(&proxy, &surrogate.token, "GET", "/user", &[], b"")?;
```

Servers: `broker::Broker::from_file(path)?` and `proxy::Proxy::from_file(path)?`,
then `Arc::new(..).serve()?`. Alternative token endpoints implement
`broker::TokenEndpoint`; alternative key custody implements the core traits
`stateless::SurrogateSealer` / `SurrogateOpener`; a TPM or HSM client key is a
`tls::ClientIdentity::Resolver` (feature `tpm` provides the tpm2-tools signer).

## Command line

`cargo install --path crates/garrett-stateless` installs
`garrett-stateless` (the Python package installs a command with the same
interface). Run it without arguments for usage: `keys`, `pki`, `broker`,
`proxy`, `mint`, `inspect` and `agent login|renew|request`.

## What is proved

Every security decision is made by Aeneas-extracted controllers in
`garrett-stateless-core` (`stateless`, `stateless_login`,
`stateless_proxy`); `proofs/GarrettStateless*.lean` proves properties of that
extracted code. Ed25519, AES-GCM, TLS/X.509, the token endpoint and the OS
are trusted adapters. See `docs/verification.md`.
