# The article, feature by feature

This profile implements the architecture as the article describes it:
[specification](garrett-stateless-v1.md), [usage](usage.md) and
[proofs](verification.md).
The article uses neither "OAuth" nor "stateless", but it describes both
behaviours: a browser login whose result returns to the broker, and "no
persistent data is ever held in the broker or the proxy". Its section 14
separates what the article requires from the engineering choices added here:

- OAuth code flow with PKCE;
- an AEAD-sealed `state`;
- a transient login mailbox (the article does not say how the result reaches
  the agent);
- a claim-copy policy that defaults to access claims, because provider claims
  can be personal data;
- renewal up to an absolute cap, and key retirement as revocation;
- a reverse proxy whose destination is chosen by the authenticated provider
  claim.

| Article feature | `garrett-stateless-v1` | Evidence |
| --- | --- | --- |
| Agent asks a central broker, authenticated by its certificate | mTLS agent API | Python and Rust, four-way interop |
| Browser login whose redirect returns to the broker | authorization code + PKCE; broker-owned callback; sealed state; confirmation code | synthetic HTTPS IdP; `GarrettStatelessLogin`, `GarrettStatelessMailbox`, `GarrettStatelessState` |
| Wrapper JWT: copied claims, encrypted real token, certificate representation, broker signature | `garrett-stateless-v1+jwt`; `upstream`, `enc`, `cnf`, Ed25519 | shared vectors; `GarrettStateless`, `GarrettStatelessToken` (`verify_token_sound`, `seal_token_ok`) |
| Proxy: mTLS, certificate match, decrypt, swap, forward | stateless mTLS reverse proxy | `GarrettStatelessProxy`, `GarrettStatelessConnection`, `GarrettStatelessProtocol` (`send_origin`) |
| No persistent data; scale by starting instances | the pure `stateless_proxy::decide`; restart and replica tests; an optional strict mode that refuses the OAuth mailbox and the audit file, the only state beyond keys and configuration | `replicas_decide_alike`, `replicas_differ_only_by_answers`, `strict_no_login_state`; tests and demo |
| Opaque provider tokens and API keys | `oauth` or `provisioned` providers; minting needs no OAuth client | spec section 7.1; strict interop tests |
| Proxy decides by the token alone | Garrett's proxy is the default; a read-only proxy (spec section 11.1) narrows a surrogate to listed `GET`/`HEAD` resources, by static configuration (an addition beyond the article) | `composed_egress`, instantiated by `garrett_egress` and `read_only_egress`; `tests/test_garrett_stateless_operations.py`; `STATELESS-OPS-01` |
| JWT and opaque provider tokens | both | tests, vectors |
| Hardware or hypervisor-backed instance key | optional TPM signer (Rust agent) | swtpm test only; no hardware provenance |

This is a project-specific wire profile, not an interoperable standard (the
article specifies no wire format). It is experimental and unaudited.


## The composed protocol theorem

- **The internal `garrett-stateless-v1` protocol.** `GarrettStatelessProtocol`
  composes the extracted mailbox, token codec, key set, admission, renewal and
  proxy connection loop into `protocol_safety`, over every finite execution
  with arbitrary clocks, randomness, peers, OAuth answers and channel
  behaviour. Its only premises are the external boundary of
  `GarrettStatelessBoundary` (AES-GCM correctness for paired keys; no
  Ed25519 forgery in the execution). The native shells' I/O is checked by a
  source guard, not proved ([details](verification.md)).
