# HTTPS proxy profiles: compatible credential use beside named operations

**Status: new priority (maintainer, 2026-10-23). Planning only; nothing here
is implemented or verified yet.** Work items are `HP-0`..`HP-7`. They join the
[active queue](aivm-secrets-active-work.md) and the
[product roadmap](aivm-secrets-product-roadmap.md) as outcome `OUT-6`.

## Why

Today a guest uses a credential only through named operations (`pr.view`
with typed arguments). That is the strongest model, but stock tools such as
`gh`, `curl` and SDKs cannot use it unchanged. The maintainer wants an
optional, **more broadly compatible** host policy as well: a Docker-sandbox
style HTTPS proxy that substitutes the credential. The restrictive profile
must stay available and must not be weakened to look like a proxy.

The organizing rule: **separate how the guest asks from what authority the
host grants.** One host-owned custody, identity, audit and revocation core
serves several guest-facing frontends. Each frontend has an explicitly
named security profile, and the operator selects one per credential.

## The three profiles

| Profile | Guest interface | Authority the guest gets | Strongest intended claim |
| --- | --- | --- | --- |
| `named-operation` (current) | Typed operation (`pr.view {repo, pr}`); host builds the request; disclosure-selected reply | Exactly the policy's operations and arguments | Every credential-bearing effect comes from a currently authorized named operation; the guest sees only the declared release and public protocol behaviour (NR-0..NR-5) |
| `constrained-http` (new) | Ordinary HTTPS via a proxy; each request must match a finite allowlist of request shapes that translate to named operations | Same as named operations, for the supported shapes | Every credential-bearing request conforms to a currently authorized host policy over destination, method, path, parameters and relevant body; responses are released per the operation's disclosure |
| `credential-substitution` (new) | Ordinary HTTPS via a proxy; the proxy replaces a placeholder credential for configured origins | **Everything the credential can do at the configured origins** | The credential is not a guest input; injected authentication goes only to configured origins; responses carrying the credential are refused |

Operator guidance, recorded in the profile metadata: use
`credential-substitution` only for narrowly scoped credentials, such as a
model-provider key with no account-administration power. Use
`named-operation` or `constrained-http` for broad credentials, such as a
GitHub token that can read many private repositories or merge pull requests.

### Non-negotiable rules

1. **No silent fallback.** A request `constrained-http` does not recognise is
   refused. It is never retried through `credential-substitution`.
2. **Per-credential opt-in.** A credential is usable by
   `credential-substitution` only if its host policy says so explicitly. The
   default is named operations only.
3. **One custody core.** No proxy holds a second copy of the credential or
   reimplements custody, unsealing, OAuth refresh, revocation or audit.
4. **Optional everywhere.** The proxy is a separately enabled frontend. Normal
   AIVM never requires it, and AIVM reaches it only through a versioned
   process contract, as with `native-session`.
5. **Honest claims.** `credential-substitution` makes no authority-confinement
   claim. Neither proxy profile inherits the NR theorems; each needs its own
   refinement to the core (HP-5, HP-6).

## Security comparison

| Property | `credential-substitution` | `constrained-http` | `named-operation` |
| --- | --- | --- | --- |
| Original credential never installed in the guest | Yes | Yes | Yes |
| Credential sent only to configured origins | Yes | Yes | Yes (host-selected destination) |
| Restrict repositories/objects | No | Yes, for allowlisted shapes | Yes |
| Prohibit specific API operations | Deny-list only | Yes (allowlist) | Yes |
| Restrict parameters and body | No | Yes, for allowlisted shapes | Yes |
| Restrict response fields | No (raw response, reflection-checked) | Yes (operation disclosure) | Yes |
| Credential amplification (API mints a new credential) | **Not prevented in general**; known minting endpoints are deny-listed per provider | Prevented unless an allowlisted shape mints | Prevented unless a named operation mints |
| Formal target | HP-5 | HP-6 | NR-0..NR-5 |

Credential amplification is the main reason substitution is weaker than it
looks. Keeping the original token out of the guest does not stop the guest
from asking the provider for a *new* credential and reading it back. The
reflection check refuses responses that contain the *original* credential
bytes. It cannot recognise a freshly minted one.

## Network mediation is a separate, AIVM-side question

Checked against `../aivm/aivm/firewall.py`: the forward chain drops the
configured blocked CIDRs (private ranges) and then **accepts** all other
forwarded guest traffic. Setting `HTTPS_PROXY` in a guest therefore routes
only cooperating tools through the proxy. Other processes can still reach
public origins directly, just without the credential.

Under both proxy profiles the credential still cannot leave through a
non-proxied path, because only the proxy holds it. What is **not** claimed is
that "all guest traffic is mediated". A Docker-style default-deny egress is
an optional AIVM network mode (HP-7). It is out of scope for the broker and
must stay opt-in.

## Architecture

```
guest tool ──HTTPS_PROXY──> guest loopback port ══ssh -R══> host proxy socket
   (placeholder token,                                      │ authenticate session (surrogate)
    trusts session CA)                                      │ CONNECT origin ∈ policy?
                                                            │ TLS terminate (leaf for that origin only)
                                                            │ strict HTTP/1.1 parse → canonical request
                                                            ├─ credential-substitution: strip guest auth,
                                                            │    inject credential, re-encode, send
                                                            └─ constrained-http: translate → named operation
                                                                 → existing dispatch (host-built request)
                                                            │ audit, response reflection check,
                                                            │ re-frame response to guest
```

- **Session authentication.** The guest presents a per-session surrogate in
  `Proxy-Authorization`. A bound profile may require the existing mTLS client
  identity instead. Every request re-checks revocation and expiry, using the
  same current-control model as the broker.
- **TLS interception.** Each session gets a CA generated on the host. Its key
  never leaves the host, and it carries X.509 `nameConstraints` limiting it
  to the configured origins. The guest trusts only this CA. Leaf certificates
  are minted only for allowed origins, and only HTTP/1.1 is offered (ALPN).
- **Strict request parsing.** The parser accepts one request at a time and
  rejects ambiguity: `Content-Length` together with `Transfer-Encoding`,
  duplicate or invalid `Content-Length`, any transfer coding except `chunked`,
  obs-fold, bare CR or LF, absolute-form or authority-form targets inside the
  tunnel, a `Host` that differs from the CONNECT origin, `Upgrade`, `Expect`
  (in the prototype), and header or body sizes over policy bounds.
- **Re-encoding, not passthrough.** The upstream request is the proxy's own
  canonical encoding of the parsed request. It reuses the verified request
  line, header and auth appenders (`http_wire`, `http_auth`). Guest-supplied
  `Authorization`, `Proxy-*`, `Cookie` (unless the policy allows it) and
  hop-by-hop headers are removed. The credential line is injected once.
- **Upstream destination.** Each origin's address, port and CA are pinned by
  host policy, as in the existing `egress` pin. The proxy never resolves an
  origin to a destination the policy did not name. Redirects are not
  followed: a `3xx` goes back to the guest, and any new origin must pass the
  CONNECT check itself.
- **Responses.** In the prototype the proxy buffers each response up to a
  policy cap. It refuses a response whose status line, headers or body
  contains the credential bytes, or common encodings of them (base64, URL
  encoding). The refusal is a fixed `502` with a fixed body. The response is
  re-framed with `Content-Length`. Streaming is out of scope until HP-4.
  The proxy always sends `Accept-Encoding: identity` upstream and refuses any
  response with a `Content-Encoding`, so the reflection check never runs
  over compressed bytes.
- **Deny-list (substitution).** The policy lists method and path patterns the
  proxy refuses even in substitution mode, such as GitHub token or key
  creation, `DELETE /repos/...` and `PUT .../merge`. This narrows authority
  but is a best-effort list, not confinement.
- **Audit.** Each request records origin, method, normalised path, profile,
  decision and status. No credential, header values or body bytes are
  logged.

## Work items

| ID | Item | Acceptance |
| --- | --- | --- |
| **HP-0** | This plan; the proxy policy schema (profile name, origins with pinned address/CA/authentication, deny list, limits, lifetime); assumption-ledger entries for the new boundaries. The existing [assurance profiles](aivm-secrets-assurance-profiles.json) compare *identity binding* (local, bound key, vTPM), a different axis, so interface profiles are not mixed into that table. **Done 2026-10-23:** schema in `aivm_secrets/proxy/policy.py`; ledger rows `PROXY-AUTHORITY-01`, `PROXY-PARSE-01`, `PROXY-REFLECT-01`, `PROXY-EGRESS-01`, `PROXY-TLS-01` | Reviewed plan; schema documented; ledger rows with removal roadmap; tests on schema validation |
| **HP-1** | **Done 2026-10-23 (Python reference, synthetic):** [`aivm-secrets proxy`](../https-proxy-profile.md). **Python reference prototype, `credential-substitution`**: proxy server (CONNECT, session CA, strict HTTP/1.1 parser, header rewrite, pinned upstream TLS, reflection refusal, deny-list, audit) with `aivm-secrets proxy` CLI | Synthetic TLS provider and synthetic credential; stock `curl` and Python `urllib`/`requests`-style clients through `HTTPS_PROXY`; adversarial tests: request smuggling forms, Host/CONNECT mismatch, unlisted origin, guest Authorization replaced, credential reflected in body/header/redirect, deny-listed path, revoked/expired session, oversize; credential never in guest-visible bytes or logs |
| **HP-2** | **Done 2026-10-23 (Python reference, synthetic).** Design choice: no separate shape table. The allowlist *is* the broker's schema-2 operations, and a request is accepted only if the host encoder, run on the arguments read off it, reproduces it exactly (`aivm_secrets/proxy/constrained.py`). **Python `constrained-http`**: request-shape allowlist (method, path template, query allowlist, body schema), each mapped to an existing named operation; responses released per that operation's disclosure | Shapes for a small set of GitHub REST reads; ambiguous or unknown requests refused with no provider call; no fallback to substitution (tested); same adversarial suite as HP-1 |
| **HP-3** | **Done 2026-10-23 (synthetic):** `aivm-secrets proxy-session` (Python or native proxy, CA/bundle/env published, TCP reverse forward) and the opt-in `aivm ssh --secrets_proxy_spec`; local-guest curl test for both backends. A maintainer real-VM run with `gh`/`curl` is still needed. **Process contract and optional AIVM wiring**: `native-session`-style contract that publishes the session CA and placeholder token into the guest and forwards a guest loopback port; AIVM opt-in flag | Default AIVM unchanged and never imports the package (tested); synthetic local-guest test; real-VM `gh api` / `curl` run is a maintainer action |
| **HP-4** | **Core done 2026-10-23:** `proxy_http.rs` (strict parser, field filter, deny rules, upstream encoder, response parser, reflection forms, guest re-framing) in the extracted core, with byte parity to the Python reference over 64 request and 40 response vectors. **Native server done 2026-10-23:** `garrett-proxy` (same contract and policy; 27 native tests; `PROXY-NATIVE-01`). **Rust implementation in the extracted core**: origin decision, strict request parser/validator, canonical re-encoder (reusing `http_wire`/`http_auth`), header rewrite, response reflection check; native code limited to sockets/TLS/CA minting | Byte-equality oracle against the Python reference over the HP-1 corpus; W3-style guard that the native proxy's only upstream write is the extracted encoder's output |
| **HP-5** | **(a) and (b) done 2026-10-23** in the encoder ([`GarrettProxyHttp`](../../proofs/GarrettProxyHttp.lean): `encode_upstream_contract`, `forwarded_drops`, `clean_field_single_line`); the encoder re-validates framing itself, so (b) no longer depends on the parser. **(c) done 2026-10-23** ([`GarrettProxyResponse`](../../proofs/GarrettProxyResponse.lean): a released response never contains the raw credential; response side has byte parity over 40 vectors). (d) fixed refusals open. **Aeneas/Lean proof, substitution profile** | (a) credential bytes occur in an upstream write only as the single injected auth line, on a connection whose origin is in policy; (b) guest-supplied header and body bytes cannot introduce framing (parser–encoder agreement: the encoded request parses back to the accepted request); (c) every byte released to the guest passed the reflection check (`false_search_excludes_literal`); (d) refusals are fixed frames. Named assumptions: TLS, CA minting, socket I/O, provider semantics (amplification) |
| **HP-6** | **Redesign (2026-10-23):** the native broker only dispatches named operations for a certificate-bound guest identity (`ProviderSession::request` takes the verified peer). So the native constrained profile should be a **guest-side, untrusted** HTTP-to-`invoke` translator. It holds no credential and calls the bridge like any guest tool, so every provider effect is a named operation the bridge authorizes and the NR theorems apply unchanged. The translator's correctness then affects only *which* allowed operation runs, never authority, and the Python round-trip equality check becomes a usability guard. The remaining proof obligation is that the translator adds no host trust. **Aeneas/Lean proof, constrained profile** | Every accepted HTTP request translates to exactly one named operation and arguments, and the dispatched bytes are the host encoding of that operation. This composes with the existing NR theorems, so constrained-http inherits NR guarantees only through this proved refinement |
| **HP-7** | **Optional AIVM egress mode** (in AIVM): default-deny forward chain allowing only the proxy path | Opt-in; existing firewall behaviour unchanged by default; tested in AIVM, real-VM run by maintainer |

Order: HP-0 → HP-1 → HP-2 → HP-4 (substitution parts) → HP-5 → HP-3 → HP-6
→ HP-7. HP-3 can start once HP-1 exists. The NR read campaign continues; the
proxy reuses its verified leaves (`http_wire`, `http_auth`, reflection,
public errors) rather than diverting it.

## What each profile may claim, word for word

- `credential-substitution`: *The host-held credential is not an input to the
  guest; broker-injected authentication is sent only to configured origins;
  responses containing the credential's bytes are refused.* It must **not**
  say the guest's operations are authorized, restricted or least-privilege.
- `constrained-http`: *Every credential-bearing request conforms to a
  currently authorized host policy over destination, method, path, parameters
  and the policy-relevant body; responses are released per the matched
  operation's disclosure.* Only after HP-6 may it say it refines named
  operations.
- `named-operation`: unchanged (NR-0..NR-5, OUT-1).

## Hard cases to design for (tests before claims)

Redirects to other origins; `Expect: 100-continue`; chunked bodies and
trailers; pipelining and keep-alive; HTTP/2 and HTTP/3 (refused); GraphQL,
where one URL carries many operations (substitution passes it through;
constrained mode needs a query allowlist); pagination `Link` headers to other
hosts; compressed responses (the reflection check needs a decode step, or the
proxy must refuse `Content-Encoding`); partial sends and uncertainty after
egress (never retried); SSE and streaming; provider error bodies that echo
headers; and credential-minting APIs.
