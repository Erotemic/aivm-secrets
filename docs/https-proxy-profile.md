# HTTPS proxy profile: `credential-substitution` (experimental)

**Python reference, synthetic-tested. Not proved, not the default, and
weaker than named operations.** See the
[plan](planning/aivm-secrets-http-proxy-profiles.md) for the three profiles
and what each may claim.

## What it does

`aivm-secrets proxy` holds one credential for one session. Stock tools in
the guest use it as an ordinary `HTTPS_PROXY`:

```
python -I -m aivm_secrets proxy --policy proxy.json \
    --credential-file token --audit audit.jsonl [--port N | --unix PATH]
```

It prints one line,
`{"version":1,"ready":true,"profile":"credential-substitution","listen":…,"origins":[…],"ca_pem":…,"proxy_token":…}`,
and runs until stdin reaches EOF or SIGTERM. The guest needs three things:
the session CA (`ca_pem`), the proxy address, and `proxy_token` as the proxy
password. For example:

```
HTTPS_PROXY=http://aivm:$TOKEN@127.0.0.1:PORT curl --cacert ca.pem \
    -H 'Authorization: Bearer placeholder' https://api.example.org/v1/account
```

The proxy throws away every guest credential field (`Authorization`,
`X-Api-Key`, `Cookie`, `Proxy-*`) and injects the host credential for that
origin. The guest never receives it.

## Policy

```json
{
  "schema": 1,
  "profile": "credential-substitution",
  "lifetime_seconds": 3600,
  "origins": [{"host": "api.example.org", "address": "203.0.113.7", "port": 443,
               "ca_file": "/etc/ssl/certs/ca-certificates.crt",
               "authentication": "bearer"}],
  "deny": [{"method": "POST", "path": "/v1/tokens"},
           {"method": "*", "path": "/v1/admin/"}],
  "limits": {"request_body": 1048576, "response_body": 8388608}
}
```

`authentication` is `bearer`, `token` (GitHub style) or `x-api-key`. The
upstream address and trust anchor are pinned; nothing is resolved from what
the guest sends. A `deny` path ending in `/` covers everything below it.

## What is enforced (tested in `tests/test_proxy_substitution.py`)

- CONNECT is accepted only with the session token, and only for a
  configured origin on port 443. Plain HTTP proxying is refused.
- Interception uses a per-session CA held in memory. It is name-constrained
  to the configured origins and mints leaves only for them.
- Requests must fit a strict HTTP/1.1 subset. Refused: `Content-Length`
  together with `Transfer-Encoding`; duplicate lengths; non-chunked codings;
  obs-fold; bare CR or LF; a `Host` mismatch or duplicate; dot or empty
  segments; encoded `.`, `/` or `\`; `Upgrade`; `Expect`; HTTP/1.0;
  absolute-form; and methods outside GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS.
- The upstream request is the proxy's own canonical re-encoding:
  `Accept-Encoding: identity`, one connection, and an exact
  `Content-Length`.
- Deny-listed requests and revoked or expired sessions are refused before
  egress. Revocation is re-checked on every request, including inside an
  open keep-alive tunnel.
- Responses are refused if they contain the credential raw, percent-encoded,
  hex, or base64/base64url at any offset, or if they are compressed.
  Redirects are returned, never followed.
- Refusals are fixed JSON bodies. The audit is a hash-chained JSONL of
  decisions (origin, method, path, status, code) with no header values or
  bodies.

## What it does not do

- **No authority confinement.** The guest can do whatever the credential
  can do at a configured origin, except deny-listed requests. That includes
  minting new credentials, which the reflection check cannot recognise
  (`PROXY-AUTHORITY-01`). Use it only for narrowly scoped credentials.
- **No network mediation.** Only tools that honour `HTTPS_PROXY` go through
  it, and AIVM's default firewall allows other public egress
  (`PROXY-EGRESS-01`). The credential still cannot leave by another path.
- No HTTP/2, streaming, `Expect`, trailers or compressed responses yet.
- Not yet ported to Rust or proved (HP-4, HP-5).
