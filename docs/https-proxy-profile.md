# HTTPS proxy profiles (experimental)

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

`authentication` is `bearer` (`Authorization: Bearer …`) or `x-api-key` (`X-API-Key: …`). The
upstream address and trust anchor are pinned; nothing is resolved from what
the guest sends. A `deny` path ending in `/` covers everything below it and
the path without the slash; any rule also matches its path plus a trailing `/`.

## What is enforced (tested in `tests/test_proxy_substitution.py`)

- CONNECT is accepted only with the session token, and only for a
  configured origin on port 443. Plain HTTP proxying is refused.
- Interception uses a per-session CA held in memory. It is name-constrained
  to the configured origins and mints leaves only for them.
- Requests must fit a strict HTTP/1.1 subset. Refused: `Content-Length`
  together with `Transfer-Encoding`; duplicate lengths; non-chunked codings;
  obs-fold; bare CR or LF; a `Host` mismatch or duplicate; dot or empty
  segments; `#`, `\` or `;`; malformed `%` escapes and escapes of unreserved
  characters, `/`, `\`, NUL or `;` (so `/%61dmin` cannot dodge `/admin/`);
  `Upgrade`; `Expect`; HTTP/1.0;
  absolute-form; and methods outside GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS.
- The upstream request is the proxy's own canonical re-encoding:
  `Accept-Encoding: identity`, one connection, and an exact
  `Content-Length`. Guest credential, hop-by-hop, cookie, method-override
  (`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`) and
  `Range`/`If-Range` fields are dropped (19 names, any case).
- Deny-listed requests and revoked or expired sessions are refused before
  egress. Revocation is re-checked on every request, including inside an
  open keep-alive tunnel.
- Responses are refused if they contain the credential raw, JSON-escaped
  (`\/`), percent-encoded, hex, or base64/base64url at any offset (also with
  line breaks removed, so MIME-wrapped base64 is caught), or if they are
  compressed.
  Redirects are returned, never followed.
- Refusals are fixed JSON bodies. The audit is a hash-chained JSONL of
  decisions (origin, method, path, status, code) with no header values or
  bodies, opened `0600` without following symlinks.
- Resource bounds: at most 32 concurrent connections, a 30 s deadline for
  the request head and 120 s per request, and a bounded raw buffer.

## What it does not do

- **No authority confinement.** The guest can do whatever the credential
  can do at a configured origin, except deny-listed requests. That includes
  minting new credentials, which the reflection check cannot recognise
  (`PROXY-AUTHORITY-01`), and a provider that honours a method override in
  the query or body (such as `_method`) can still reach a denied action.
  Use it only for narrowly scoped credentials.
- **No network mediation.** Only tools that honour `HTTPS_PROXY` go through
  it, and AIVM's default firewall allows other public egress
  (`PROXY-EGRESS-01`). The credential still cannot leave by another path.
- No HTTP/2, streaming, `Expect`, trailers or compressed responses yet.

## `constrained-http`

```
python -I -m aivm_secrets proxy --policy proxy.json --credential-file token \
    --audit proxy.jsonl --service-policy service.json --broker-audit broker.jsonl \
    [--writes deny|allow]
```

With `"profile": "constrained-http"`, the proxy policy names exactly one
origin, `{"host": …}`, which must be the service policy's host. It carries
no address, trust anchor, credential scheme or deny list. The proxy holds
**no credential**. It runs the ordinary broker in-process for
`service.json`, a schema-2 HTTPS policy, and serves a guest request only
when it is **exactly** one of that policy's named operations:

1. Arguments are read off the request against each operation's method,
   path template and query template.
2. The broker's own encoder is run on those arguments. The request is
   accepted only if that encoder reproduces the guest's method, path, query
   (order-insensitive, no duplicates) and JSON body. A matcher defect
   therefore cannot widen authority.
3. The broker re-checks scope and write mode, builds and sends the provider
   request itself, and returns only the operation's disclosure as the
   response body.

Anything else is `403 unsupported_request`, with no provider call. There is
no fallback to substitution: one session runs one profile, and a
constrained session has no credential to substitute. Operations with a
host check (`requires`) are translated when their final target comes from
the arguments alone (the host runs the check itself, as for any named
request); operations whose target needs the check's facts (such as a head
SHA), pinned GraphQL documents and `returns: check` are not. Tests:
`tests/test_proxy_constrained.py`.

The response is the operation's disclosure, not the full provider response.
Stock tools that need fields the policy does not release will fail rather
than receive them (HP-3 tests compatibility).

### Guest side, over the native bridge (HP-6)

```
python -I -m aivm_secrets proxy --policy proxy.json --audit proxy.jsonl \
    --service-policy routes.json \
    --bridge-client '["garrett-client", "--config", "client.json"]'
```

The same translator can run **inside the guest**, untrusted. It takes no
credential (a `--credential-file` next to `--bridge-client` is refused) and
no broker audit. `routes.json` is a public copy of the host's schema-2
policy, used only for its route templates. Each translated operation goes
through the guest's native client, `invoke`, to the host bridge, which
re-checks the operation, its arguments, scope and write mode on its **own**
policy, builds the provider request and releases only the disclosure. So:

- the native-read theorems apply to every provider effect unchanged;
- a wrong or tampered `routes.json` can only make the translator ask for a
  different named operation, which the bridge allows or refuses as it
  would for any guest tool. `tests/test_proxy_guest_translator.py` widens
  the guest copy and checks that the provider still sees nothing.

The native `garrett-proxy` runs the same mode without Python:

```
garrett-proxy --policy proxy.json --audit proxy.jsonl --routes routes.json \
    --bridge-client '["garrett-client", "--config", "client.json", "--capability-file", "cap"]'
```

It accepts a request only if the extracted `route_match::translate` finds
arguments under which the host's own `route::fill_target` writes the target
back byte for byte (proved: `translate_round_trip`); a parameter's allowed
texts let one value span `/` (such as `owner/repo`). The typed arguments
reproduce the method, target and JSON body through the route copy's request
validation. Differences from the Python translator: the query must be in
the policy's (sorted) order, a path parameter without allowed texts is one
segment, and a bridge error is reported as `denied`, `invalid_request`, `revoked` or
`outcome_unknown`.

## Native `garrett-proxy`

The same profile, with the same policy file and process contract, runs as
the native binary `garrett-proxy --policy P --credential-file F --audit A
[--port N]`. It is a thin I/O shell (sockets, rustls, rcgen session CA,
audit, stdin lease). Every parse, encode, filter, reflection and re-framing
decision is a call into the Aeneas-extracted `proxy_http` core. Two
theorems apply to it: the credential appears upstream only as the single
verified authentication line (`encode_upstream_contract`), and a released
response never contains the raw credential (`guest_response_contract`).
What the shell itself writes is pinned by a source-shape test, not proved
(`PROXY-NATIVE-01`). Tests: `tests/test_rust_proxy.py`. The constrained-http
profile is Python only for now.

## Giving a guest the proxy: `proxy-session` and AIVM

```
python -I -m aivm_secrets proxy-session --spec SPEC
```

`SPEC` has exactly these keys: `version` (1); `bin_dir` (the directory of
`garrett-proxy`, or `null` for the Python reference); `policy_file`,
`credential_file`, `audit_file` (host-private); `guest_port` (a guest
loopback port, 1024–65535); and `guest` (`{"kind":"ssh","ssh_config":…,"host":…}`,
or `{"kind":"local"}` for tests). The child starts the proxy and creates a
fresh guest directory. There it publishes the session CA, a CA bundle (the
guest's system roots plus the session CA) and an `env` file that sets
`HTTPS_PROXY` (with the session token) together with `SSL_CERT_FILE`,
`CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`. It then
forwards the guest port to the proxy over SSH and prints one line:
`{"version":1,"ready":true,"profile":…,"origins":[…],"guest":{"dir":…,"env":…,"ca":…}}`.
The announcement carries no token and no credential. Closing stdin stops
the proxy and the forward and removes the guest directory.

In AIVM, `aivm ssh --secrets_proxy_spec TEMPLATE` (the spec without `guest`)
runs this contract with a strict, self-contained SSH route. It sources the
`env` file before the login shell. Like `--secrets_native_spec`, it is
process-only, excludes the other `--secrets_*` options and leaves default
`aivm ssh` unchanged.

Every HTTPS request from a tool that honours `HTTPS_PROXY` goes through the
proxy, and the proxy refuses origins the policy does not list. The proxy is
never an open relay, so such tools cannot reach unlisted HTTPS hosts while
the env file is sourced. Tools that ignore `HTTPS_PROXY` are not mediated
(`PROXY-EGRESS-01`). To close direct egress, set AIVM's
`firewall.public_egress = false`. Every new guest-initiated forwarded
connection is then dropped, while the proxy keeps working because it rides
the host-initiated SSH session. This is unit-tested in AIVM; a real-VM check
is a maintainer action.

## Real-VM check (maintainer, opt-in)

```
python dev/aivm_proxy_acceptance.py --vm aivm-2404 [--python] [--egress-check]
```

The script runs `proxy-session` against a synthetic loopback provider and a
synthetic credential, using the VM's own SSH configuration. It checks five
things: stock `curl` in the guest reads an allowed path through the
published env file; the provider sees exactly one substituted credential;
an unlisted origin is refused with no provider traffic; no guest session
file contains the credential; and teardown removes the guest directory.
`--egress-check` also reports whether direct public egress is reachable. It
should be `false` only with AIVM's `firewall.public_egress = false`. The
summary always states `authority_confinement_claimed: false`.
