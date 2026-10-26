# `garrett-stateless-v1`: normative protocol specification

**Status:** experimental, unaudited. Version 1 of a project-specific wire
profile. It implements the architecture Matthew Garrett described in
[*Securing agentic identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/)
(July 2, 2026). That article is a design proposal, not a wire standard, so
this profile is **not** interoperable with any other implementation unless it
follows this document. It is not JOSE/JWE or RFC 8705 compliance either. It
uses the RFC 8705 `x5t#S256` confirmation *value* and a compact JWS-like
encoding.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

This profile is separate from the stateful `manifest-https-v1` AIVM profile
and from the nested `aivm-bound+jwt` / `aivs1` surrogate. No component of
this profile reads an enrollment registry, a grant, a credential vault, a
broker session or an audit log to decide whether a surrogate may be used.

## 1. Actors and trust

| Actor | Holds | Trusted for |
| --- | --- | --- |
| **Agent** | its client certificate and private key (software, TPM or vTPM); surrogates | nothing; it is untrusted |
| **Agent CA** | issues agent client certificates | identity: who an mTLS peer is |
| **Broker** | signing keys, sealing keys, login-state key, OAuth client registration | running the OAuth flow and minting surrogates |
| **Proxy** | verification keys, sealing keys, provider routes | opening surrogates and substituting credentials |
| **Human** | provider account | approving access in a browser |
| **Provider** | OAuth authorization server and API | unchanged; outside our control |

The broker and proxy keep **no persistent data**. Their only long-lived inputs
are configuration and keys, given at startup (Garrett: "No persistent data is
ever held in the broker or the proxy"). Section 9 lists the one transient
in-memory structure, the login mailbox.

## 2. Encodings

- **b64url**: RFC 4648 §5 base64url without padding. A decoder MUST reject
  padding, characters outside the alphabet, and non-canonical trailing bits
  (the re-encoding of the decoded bytes must equal the input).
- **Canonical JSON**: UTF-8 JSON with no insignificant whitespace, object
  members sorted by key (byte order), separators `,` and `:`, and strings
  escaped only for `"` and `\`. Every string this profile *emits* is
  printable ASCII (0x20-0x7e), so no other escape can occur. Integers are
  written in shortest decimal form. A parser MUST reject duplicate keys,
  non-integer numbers in security claims, nesting deeper than 16, and any
  input whose canonical re-encoding differs from the received bytes (for
  headers, payloads and login state).
- **Time**: integer seconds since the Unix epoch, `0 <= t <= 2^53 - 1`.

Grammars (all ASCII):

| Name | Grammar |
| --- | --- |
| `text` (issuer, audience, subject) | 1-256 bytes of 0x21-0x7e excluding `"` and `\` |
| `provider` | `[a-z0-9][a-z0-9._-]{0,63}` |
| `kid` | `[A-Za-z0-9][A-Za-z0-9_-]{0,31}` |
| `jti`, `login` | 32 lowercase hex digits (128 random bits) |
| `thumbprint` | b64url of SHA-256 of the certificate DER: 43 characters |
| `credential` | 1-4096 bytes of 0x21-0x7e (RFC 6750 `b64token` is a subset) |
| `scope` | 0-1024 bytes: space-separated tokens of 0x21-0x7e excluding `"` and `\` |

## 3. Keys

Each **key set** entry is identified by a `kid` and contains:

- an **Ed25519** signing key pair (the broker holds the 32-byte seed; proxies
  hold only the 32-byte public key);
- a 32-byte **AES-256-GCM sealing key** shared by broker and proxies;
- the `issuer` that entry is allowed to sign for.

The broker additionally holds a 32-byte AES-256-GCM **login-state key**. It is
never given to a proxy. Every key has exactly one purpose; AEAD inputs carry a
distinct domain label (sections 4.3 and 8.2).

Broker key file (`schema` exactly as shown; keys b64url):

```json
{"active":"k2","keys":[{"issuer":"https://broker.example","kid":"k1","seal":"...","sign":"..."},
 {"issuer":"https://broker.example","kid":"k2","seal":"...","sign":"..."}],
 "schema":"garrett-stateless-v1/broker-keys","state":"..."}
```

Proxy key file, derived from it by `keys export` (no `sign`, no `state`):

```json
{"keys":[{"issuer":"https://broker.example","kid":"k1","seal":"...","verify":"..."}],
 "schema":"garrett-stateless-v1/proxy-keys"}
```

At most 8 entries, distinct `kid`s. The broker signs only with `active`.
A proxy accepts any listed `kid`. See section 10 for rotation.

## 4. Surrogate token

A surrogate is the ASCII string `b64url(H) "." b64url(P) "." b64url(S)`,
at most **16384 bytes**.

### 4.1 Header `H`

Exactly the canonical JSON

```json
{"alg":"EdDSA","kid":"<kid>","typ":"garrett-stateless-v1+jwt"}
```

`typ` is the version. Any other header (different `alg`, extra member,
missing member, other `typ`, non-canonical encoding) MUST be rejected
before any key is used. There is no algorithm negotiation.

### 4.2 Payload `P`

Canonical JSON object with exactly these members (optional ones marked):

| Member | Type | Meaning | Authoritative? |
| --- | --- | --- | --- |
| `iss` | text | the broker issuer; MUST equal the `issuer` of the `kid` entry | yes |
| `aud` | text | the proxy audience | yes |
| `sub` | text | the agent's identity as authenticated at issuance (section 6.2) | informational |
| `jti` | jti | random token ID | informational |
| `prv` | provider | the provider whose credential `enc` carries; selects the proxy route | yes |
| `iat` | time | issue time | yes |
| `exp` | time | expiry, `iat < exp <= iat + max_lifetime` | yes |
| `ren` | time | renewable until, `exp <= ren <= iat + 2592000` | yes (broker) |
| `cnf` | `{"x5t#S256": thumbprint}` | certificate binding | yes |
| `enc` | b64url | sealed provider credential (4.3) | yes |
| `scope` | scope | *optional*; scope reported by the token endpoint | informational |
| `upstream` | object | *optional*; claims copied from a provider JWT (4.4) | **never** |

Unknown members MUST be rejected. `max_lifetime` is a proxy and broker
setting, 1-86400 seconds, default 3600.

### 4.3 `enc`: the sealed credential

```
nonce      = 12 random bytes
aad        = "garrett-stateless-v1/credential" 0x00 canonical(H) 0x00 canonical(P without "enc")
ciphertext = AES-256-GCM(seal key of kid, nonce, credential, aad)   (ciphertext || 16-byte tag)
enc        = b64url(nonce || ciphertext)
```

The plaintext is the provider credential bytes, nothing else. A decrypted
plaintext that is not a `credential` MUST be rejected. The AAD binds the
ciphertext to every other claim and to the header (`kid`), so `enc` cannot be
moved into another token.

### 4.4 Copied provider claims (`upstream`)

Garrett proposes copying the provider token's non-secret claims so that the
agent can inspect what it has. A provider claim never becomes a
broker claim. Here is how the broker treats each case:

- If the provider access token is **opaque** (not three b64url parts whose
  middle part decodes to a JSON object without duplicate keys), `upstream` is
  omitted.
- Otherwise members of the provider payload are copied **under `upstream`**,
  keeping their names, when the provider's **claim policy** (`copy_claims`,
  section 12) allows the name, the name is 1-128 bytes of 0x21-0x7e
  excluding `"` and `\`, and the value is one of: a string of 0-1024
  printable ASCII bytes, an integer with magnitude `<= 2^53 - 1`, `true`,
  `false`, `null`, or an array of at most 32 such scalars. Any other member
  is **omitted** (not an error). Non-integer numbers, objects and non-ASCII
  strings are omitted as well.
- The claim policy matters because provider claims can be **personal data**
  (names, e-mail addresses, group memberships), and the agent environment is
  untrusted. The default (`copy_claims` absent) copies only claims that
  describe the *access*, which is what Garrett gives as the reason to copy:
  `aud`, `azp`, `client_id`, `exp`, `iat`, `iss`, `jti`, `nbf`, `scope`,
  `scp`. `"copy_claims": "all"` copies every copyable claim, which is Garrett's
  proposal as written. A list copies exactly the named claims. Operator
  minting uses the provider's policy as well.
- If `canonical(upstream)` would exceed 4096 bytes, `upstream` is omitted
  entirely.
- **Collisions cannot happen**: upstream `iss`, `aud`, `exp`, `cnf`, `sub` and
  so on live under `upstream.iss`, `upstream.aud`, etc. A verifier MUST NOT
  read anything under `upstream` for any decision. The broker does not verify
  the provider's JWT signature. The claims are what the token endpoint
  returned over its authenticated TLS channel. They are signed by the broker
  as copied, not as validated.
- The provider token's signature segment is never copied.

### 4.5 Signature

`S = Ed25519(sign key of kid, ASCII(b64url(H) "." b64url(P)))`.

## 5. Opening a surrogate (proxy and broker renewal)

Inputs: the token, the key set, an **acceptance policy** (accepted audiences,
accepted providers, `max_lifetime`, clock `skew` 0-300 seconds, default 60),
the authenticated TLS peer thumbprint `peer`, and the trusted clock `now`.

The steps MUST run in this order. Any failure rejects the token. No later step
runs after a failure.

1. Length `<= 16384`; three b64url parts; the header is exactly 4.1.
2. Look up the `kid`. Unknown `kid` → reject.
3. Verify `S` with that `kid`'s Ed25519 public key over the exact received
   `b64url(H) "." b64url(P)` bytes.
4. Parse `P` (canonical, closed member set, types and grammars of 4.2).
5. **Admission** (`stateless::admit`, extracted):
   - `iss` equals the `kid` entry's issuer;
   - `aud` is an accepted audience;
   - `prv` is an accepted provider;
   - lifetime: `iat < exp <= iat + max_lifetime` and `exp <= ren <= iat + 2592000`;
   - `iat <= now + skew` (not yet valid otherwise) and `now < exp` (expired otherwise);
   - `cnf.x5t#S256` equals `peer`.
6. Only now: AES-256-GCM-open `enc` with the `kid` entry's seal key and the AAD
   of 4.3.
7. The plaintext is a `credential`.

`peer` MUST come from the certificate the TLS stack verified in the
current handshake (the first certificate of the peer chain, as DER). A
header, query parameter, or body field MUST never supply it.

## 6. Agent identity

### 6.1 Client certificates

The agent authenticates with TLS 1.3 client authentication. The peer chain
must validate to the configured agent CA, with the `clientAuth` extended key
usage. Two key-custody modes are supported:

- **software** (default): a PEM private key file;
- **tpm**: the Rust client signs the TLS CertificateVerify inside a TPM 2.0
  (physical or vTPM) through `tpm2-tools`, reusing the existing
  `aivm-secrets-garrett` TPM signer (feature `tpm`).

These modes give **different guarantees**, and none of them is
implied by a successful mTLS connection alone:

1. *An authenticated certificate*: the peer's chain validated to the agent CA.
2. *A usable key*: the peer can sign with the certified key.
3. *A non-exportable key*: the private key cannot be read out (TPM mode,
   if the key was created non-duplicable and the TPM is genuine).
4. *A key proven to belong to an environment*: requires separately
   verified attestation (EK/AK provenance). This profile does **not** check it
   at use time. The CA must do so before certifying a TPM key.
5. *No relay*: nothing here prevents a compromised agent from relaying its
   own legitimate signing operations or TLS connection to an attacker.

A copied software key and certificate impersonate the agent. That is the
accepted counterexample for software mode.

### 6.2 Subject

`sub` is the first `uniformResourceIdentifier` subject alternative name of the
agent certificate when it is a `text` (for example a SPIFFE ID). Otherwise it
is `"x5t#S256:" + thumbprint`. It is informational. The binding is `cnf`.

## 7. Issuance

The broker computes the window (`stateless::issue_window`, extracted):

```
cap = min(certificate notAfter, credential expiry)        (credential expiry = now + expires_in, or +∞)
ren = min(now + max_renew, cap)
exp = min(now + lifetime, ren)                             (lifetime <= max_lifetime)
require now < exp
```

`max_renew` is a broker setting, 0-2592000 seconds, default 604800. The
claims are then `iss`/`aud` from the broker configuration and `prv` from the
completed login. `cnf` and `sub` come from the certificate the agent presented
when it **started** the login (section 8), never from the browser. The `jti` is
fresh randomness and `iat = now`. The sealed credential is the access token the
token endpoint returned.

**Renewal** (`POST /v1/renewals`): the agent presents a currently valid surrogate
over mTLS. The broker opens it (section 5, with its own audience and
providers, so the agent's certificate must match `cnf`). It then mints a new one
for the same `prv`, `cnf`, `sub`, `scope`, `upstream` and credential, with
`credential expiry := old ren`. Renewal therefore can **never** extend
`ren`. It needs no stored state and no refresh token.

**Direct minting** (operator tool `mint`): the trusted operator gives the
credential, provider and agent certificate directly, for API keys or
synthetic tests. It uses the same window and sealing.

## 8. Agent-initiated OAuth acquisition

The broker runs two TLS listeners:

- the **agent API**, which requires client certificates;
- the **browser endpoint** (server authentication only), whose public URL
  is the registered OAuth redirect base.

The agent never runs a callback listener and never sees the authorization code
or the access token.

### 8.1 Flow

1. Agent → broker (mTLS) `POST /v1/logins` with `{"provider": P, "scope": S}`.
   `scope` is optional. It must be a subset of the provider's configured
   scopes and defaults to its `default_scope`.
2. The broker draws `login` (128 bits) and a PKCE verifier (32 random bytes,
   b64url), and builds the sealed **login state** (8.2) for the peer's
   `cnf`/`sub`/certificate expiry. It creates the mailbox entry (section 9) and
   answers `201 {"login", "authorization_url", "confirmation", "expires_at"}`.
   `authorization_url` is `<browser public URL>/authorize?state=<state>`.
   `confirmation` is `XXXX-XXXX`, the first 8 hex digits of `login`, upper case.
3. The human opens the URL. The broker's interstitial page shows the agent
   subject, the provider, the scope and the confirmation code. The human
   compares the code with the one the agent displays, then follows the link to
   the provider's authorization endpoint. That link carries `response_type=code`,
   `client_id`, `redirect_uri=<browser public URL>/callback`, `scope`,
   `state`, `code_challenge=b64url(SHA-256(verifier))` and
   `code_challenge_method=S256`.
4. The human authenticates and approves at the provider.
5. The provider redirects to `/callback?code=..&state=..[&iss=..]`, or with
   `error=..`.
6. The broker opens `state` (8.2) and checks it in the extracted
   `stateless_login::accept_callback`:
   - the replica matches;
   - the mailbox entry exists, is `Pending`, and has the same
     `login`/`cnf`/`prv`;
   - the window holds;
   - the RFC 9207 `iss` rule of the provider holds (`issuer` configured:
     `iss` required and equal; not configured: `iss` absent).
   The entry moves to `Accepted` (or `Denied` on `error=`), then to
   `Exchanging`.
7. The broker POSTs to the pinned token endpoint
   (`grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`,
   optional `client_secret`, `code_verifier`) with `Accept: application/json`.
   The response must be `200` JSON with a `credential` `access_token` and a
   `token_type` equal to `bearer` (case-insensitive). `expires_in` is
   optional (a positive integer). `scope` is optional. A `refresh_token` is
   **discarded**: it is never stored and never sealed.
8. The broker issues the surrogate (section 7) and moves the entry to
   `Complete`, holding the surrogate. Any failure after the token request was
   sent moves it to `Failed` (no retry, as the code is single use).
9. Agent → broker (mTLS) `GET /v1/logins/<login>?wait=<0..30>` returns
   - `202 {"status":"pending"}` while not complete;
   - `200 {"token", "expires_at"}` exactly once, when the peer certificate
     equals the entry's `cnf`;
   - `403 {"error":"wrong_certificate"}` for any other peer (the entry is
     unaffected);
   - `410 {"error":"login_denied"|"login_failed"|"login_expired"}`;
   - `404 {"error":"login_unknown"}`.

### 8.2 Sealed login state

```
plaintext = canonical JSON {"cert_exp","cnf","exp","iat","login","prv","rep","scope","sub","verifier"}
aad       = "garrett-stateless-v1/login" 0x00
state     = "gs1." b64url(nonce || AES-256-GCM(login-state key, nonce, plaintext, aad))
```

`exp - iat` is 1-600 seconds (`login_ttl`, default 600). `rep` is the
replica name. The state is opaque to the browser and provider. Only the broker
can read it, so the PKCE verifier stays confidential even though `state`
passes through the browser. CSRF and callback substitution are covered as
follows:

- a forged `state` fails AEAD;
- a `state` for another login names a different mailbox entry;
- an attacker's `code` was issued for a different PKCE challenge, so the
  exchange fails;
- a replayed callback finds the entry no longer `Pending`.

## 9. Transient state, and what statelessness means

**Credential use is fully stateless.** A proxy decides from (token, key set,
routes, acceptance policy, peer certificate, clock) alone. It has no token
table, registry, vault or broker connection. Any number of independent proxy
replicas with the same configuration accept the same surrogates. A restarted
proxy accepts surrogates issued before it started.

**Issuance has exactly one piece of transient state, the login mailbox.**
After the browser callback, the broker holds a finished surrogate that it
cannot push to the agent. The agent must collect it. The mailbox is:

- in memory only, never written to disk;
- bounded at 1024 entries per replica, with each entry living at most
  `login_ttl`;
- keyed by `login`, holding (`cnf`, `prv`, window, stage, and the finished
  surrogate when there is one);
- **not a credential store**: the provider credential is sealed inside the
  surrogate under the proxy sealing key, and the surrogate is bound to `cnf`;
- consumed on first successful delivery.

Losing it (restart, other replica) only loses logins in progress. The agent
starts a new login. **Replicas:** each broker replica has its own name (`rep`)
and its own browser URL, registered as a redirect URI with the provider. The
callback for a login therefore returns to the replica that created it, and the
agent polls that same replica's agent API (the `authorization_url` names it).
Replicas share keys and configuration, but no mutable state.

Garrett's article does not say how the browser's result reaches the agent.
The mailbox is this profile's answer, and it is transient state that Garrett
did not specify. The surrogate it holds is still a capability (useless without
the agent's key, but bound to it), so the mailbox follows these rules:

- **authenticated retrieval**: only an mTLS peer whose certificate equals
  the login's `cnf` receives the surrogate (`stateless_login::deliver`). Any
  other peer gets `403` and the entry is untouched;
- **single use**: a delivered surrogate is removed;
- **expiry and cleanup**: an entry is unusable after `exp` (pending) or
  `exp + 300` (complete) and is pruned on every insertion. Nothing reaches
  disk.

What pure statelessness **cannot** provide:

- immediate revocation of one surrogate;
- shared budgets or rate limits;
- one-time-use surrogates;
- audit-before-use ordering across replicas.

This profile offers short `exp`, the renewal cap `ren`, key retirement and
client-certificate expiry instead.

## 10. Key rotation and revocation

1. `keys rotate` adds a new entry to the broker key file and makes it
   `active`. Export the new proxy key file and deploy it to **all proxies
   before** the broker starts signing with it.
2. Old entries stay accepted until `keys retire <kid>` removes them. Deploy
   the retirement to the proxies to **revoke every surrogate signed under that
   kid**. Retirement is the only bulk revocation.
3. A single surrogate cannot be revoked. Its exposure is bounded by `exp`
   (default 1 hour) and, through renewal, by `ren`.
4. The login-state key MAY be rotated at any time. Logins in progress then
   fail.
5. Client-certificate **revocation lists are not checked** by this profile's
   broker or proxy; only the certificate's validity period and chain are.
   Revoking an agent therefore means retiring its CA, waiting for its
   certificate (and so its surrogates, which never outlive it) to expire, or
   retiring the key set.

## 11. Proxy

The proxy is an mTLS **reverse proxy**. Clients point their API base URL at
`https://<proxy authority>/`. Configuration:

```json
{"schema":"garrett-stateless-v1/proxy","listen":"127.0.0.1:8443","authority":"proxy.example:8443",
 "certificate":"proxy.pem","private_key":"proxy.key","client_ca":"agent-ca.pem","keys":"proxy-keys.json",
 "audiences":["https://proxy.example"],"max_lifetime":3600,"skew":60,"request_limit":1048576,
 "routes":[{"provider":"github","host":"api.github.com","address":"api.github.com","port":443,
            "ca_file":null,"authentication":"bearer","deny":[{"method":"DELETE","path":"/"}]}]}
```

`routes` has 1-16 entries with distinct providers. `authentication` is
`bearer` (`Authorization: Bearer <credential>`) or `api-key`
(`X-API-Key: <credential>`). `ca_file: null` means the system web PKI roots.
Per request (`stateless_proxy::serve`, extracted):

1. Parse the request strictly (the existing `proxy_http::parse_request`). The
   `Host` must equal `authority`.
2. Exactly one `Authorization` field, of the form `Bearer <surrogate>`,
   `token <surrogate>`, or `Basic b64(<user>:<surrogate>)` (for stock Git and
   GitHub clients). Anything else → `401`.
3. Open the surrogate (section 5) with `peer` from this connection's
   handshake. Any rejection → the fixed `401` response
   (`WWW-Authenticate: Bearer realm="garrett-stateless", error="invalid_token"`).
   The reason goes to the proxy's diagnostics, not to the client.
4. The route is the one whose `provider` equals the token's `prv`. **The
   destination is chosen by the authenticated token, never by the request.**
5. Encode the upstream request with the existing `proxy_http::encode_upstream`:
   - drop the client's credential-bearing and hop-by-hop fields;
   - set `Host` to the route `host`;
   - append exactly one authentication line with the decrypted credential;
   - add `Connection: close` and `Accept-Encoding: identity`.
   Deny rules refuse with `403`.
6. Exchange over TLS with the route's pinned `address:port`, verifying the
   route `host` against `ca_file` (or system roots).
7. Release the response with the existing `proxy_http::guest_response`.
   A response whose bytes contain the credential in any of the checked
   encodings is refused (`502`, `reflected`). Hop-by-hop fields and
   `Set-Cookie` are dropped.

Every request on a kept-alive connection is admitted independently.
Methods, request bodies, query strings and status codes pass through within
the limits of the strict HTTP/1.1 subset documented in
[HTTPS proxy profiles](https-proxy-profile.md). Not supported: `Upgrade`,
`Expect`, `Range`, request trailers, HTTP/2, and compressed response encodings.
The proxy does not restrict *which* provider API operations a token can call
(beyond deny rules). Authority confinement is the provider's scope or the
stateful profile's job.

The proxy MAY write a diagnostics/audit line per request (route, status,
`jti`, rejection reason; never credential or surrogate bytes). When an audit
file is configured, a failed write refuses the request before egress. Audit is
an operational sink, never an input to authorization.

## 12. Broker configuration

```json
{"schema":"garrett-stateless-v1/broker","issuer":"https://broker.example","audience":"https://proxy.example",
 "replica":"a","agent_listen":"127.0.0.1:9443","browser_listen":"127.0.0.1:9444",
 "public_url":"https://broker.example:9444","certificate":"broker.pem","private_key":"broker.key",
 "agent_ca":"agent-ca.pem","keys":"broker-keys.json","providers":["github.json"],
 "max_lifetime":3600,"max_renew":604800,"login_ttl":600}
```

Provider file (shared by broker and tooling):

```json
{"schema":"garrett-stateless-v1/provider","name":"github",
 "authorization_url":"https://github.com/login/oauth/authorize",
 "token_url":"https://github.com/login/oauth/access_token","token_address":null,"token_ca_file":null,
 "client_id":"...","client_secret_file":null,"issuer":null,
 "scopes":["read:user","repo"],"default_scope":"read:user","copy_claims":null}
```

`copy_claims` is `null` (access-describing claims only), `"all"`, or a list of
claim names (section 4.4).

Endpoints MUST be `https`. `token_address` optionally pins the TCP address.
`token_ca_file` optionally pins the CA. The client secret, if any, is read
from a private file and never logged.

## 13. Error discipline

- The proxy and the broker never put a provider credential, a surrogate, an
  authorization code, a PKCE verifier or a key in an error message, log line,
  diagnostic or HTTP response other than the intended one.
- Agent-visible error bodies are fixed JSON objects `{"error":"<code>"}` with
  codes from a closed list.
- A provider response that reflects the credential is refused, not
  redacted.

## 14. Relationship to Garrett's proposal

Garrett's article does not use the words "OAuth" or "stateless". It describes
the behaviour: a browser-mediated login whose result returns to the broker,
and "no persistent data is ever held in the broker or the proxy", with
encryption keys as the only state. The tables below keep what the article
requires separate from what this profile chose to fill in.

### 14.1 What Garrett's design requires, and where it is here

| Garrett | Here |
| --- | --- |
| Agent asks the broker for a token, presenting its client certificate | §8.1 step 1, over mTLS |
| Broker returns a URL; the human authenticates in a browser; the identity provider redirects back to the broker, which obtains the real token | §8.1 steps 2-8 |
| Wrapper JWT copies the original token's (non-secret) claims so the agent can inspect its access | §4.4, under `upstream`, filtered by a claim policy |
| A new claim holds an encrypted copy of the real token | §4.3 `enc` |
| A representation of the client certificate in the token | §4.2 `cnf` (`x5t#S256`) |
| Broker signs with its own key | §4.5 |
| Proxy requires mTLS, checks the certificate against the token, decrypts, swaps in the real token, forwards | §5, §11 |
| No persistent data in broker or proxy; keys injected at startup; scale by starting instances | §1, §9 |
| Opaque provider tokens are wrapped the same way | §4.4 (`upstream` omitted) |
| Instance-bound, hardware- or hypervisor-backed private key | §6, optional TPM mode, with the distinctions listed there |

### 14.2 Engineering choices this profile adds (not in the article)

| Choice | Why |
| --- | --- |
| OAuth 2.0 authorization code with PKCE (S256), RFC 9207 `iss` checking | standard, widely supported realisation of the browser flow; PKCE protects the code |
| AEAD-sealed `state` carrying the verifier and the starting peer | correlates the callback with no stored login record |
| Transient in-memory login mailbox | the article does not say how the result reaches the agent (§9) |
| Interstitial page with a confirmation code | lets the human detect a login started by someone else's agent |
| Claim names, compact JWS-like encoding, Ed25519, AES-256-GCM, AAD layout | the article names no format or algorithms |
| Claim-copy policy defaulting to access claims | provider claims can be personal data |
| `exp`/`ren` lifetimes, stateless renewal, no refresh tokens | the article does not discuss expiry or refresh |
| Key-set rotation and `kid` retirement as bulk revocation | the article does not discuss revocation |
| Reverse proxy; destination chosen by the authenticated `prv`; deny rules; reflected-credential refusal | the article says "a proxy" without a shape; these keep it from being an open relay |
| Python and Rust implementations, conformance vectors, Lean proofs | this project's assurance goals |
