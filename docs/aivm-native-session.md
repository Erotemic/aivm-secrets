# Optional native session for AIVM (process contract v1)

**Status: experimental, opt-in, synthetic-tested.** This is how an integrator
such as AIVM runs the native Rust broker for one guest without importing this
package. It is not a VM isolation claim; the deployment premises in the
[claim-to-evidence matrix](assurance/claim-evidence-matrix.md#deployment-and-custody)
still apply.

## The contract

```
python -I -m aivm_secrets native-session --spec SPEC
```

`SPEC` is a host-private JSON file with exactly these keys:

| Key | Meaning |
| --- | --- |
| `version` | `1` |
| `bin_dir` | Directory holding the native `garrett-*` binaries |
| `workspace` | Host directory for this session's authority and bridge state |
| `policy_file`, `disclosure_file`, `credential_file` | Host-private (0600) broker inputs |
| `provider` | `host`, pinned `address`, `port`, `server_ca` (0600), `authentication` |
| `binding` | `access_identity` and `vm` the session key is bound to |
| `guest` | `{"kind":"ssh","ssh_config":PATH,"host":NAME}`, or `{"kind":"local"}` for tests |
| `approve_session_key` | Must be `true`: the operator approves enrolling a fresh guest key |

The child then:

1. generates the guest key and CSR **inside the guest**;
2. checks the CSR fingerprint, enrolls it with a fresh session authority
   and starts `garrett-bridge`;
3. publishes the client, its config and the bound capability into a fresh
   `/tmp/aivm-native-*` guest directory, and forwards the bridge socket;
4. prints one line:
   `{"version":1,"ready":true,"profile":"manifest-https-v1","guest":{"dir":…,"client":…,"config":…,"capability":…}}`.

It holds the session until **stdin reaches EOF** or it receives SIGTERM. It
then stops the forward and the bridge and removes the guest directory. Any
failure prints `{"version":1,"ready":false,"error":CODE}` and exits 1. Codes:
`invalid_spec`, `missing_binary`, `guest_unreachable`, `guest_key_failed`,
`enrollment_failed`, `broker_failed`, `forward_failed`,
`credential_exposed`, `proxy_failed`. No detail text is printed.

The provider credential stays in the host bridge. The guest receives only its
own key, certificate-bound capability and client config.
`tests/test_native_session.py` performs an authorized read and an
out-of-scope denial against a synthetic TLS provider. It checks that the
token appears in no guest file, no guest output and no child output.

## The AIVM side

AIVM (`aivm ssh --secrets_native_spec TEMPLATE`) speaks only this contract,
from `aivm/secrets_native.py`. The template is the spec without `guest` and
`binding`. AIVM refuses a template that sets either, then fills them in:
`guest` with a self-contained OpenSSH config (strict host keys, no agent, no
multiplexing) and `binding` with the resolved principal and VM name. AIVM
exports `AIVM_SECRETS_NATIVE_CLIENT`, `_CONFIG` and `_CAPABILITY` into the
interactive login and closes the child's stdin when the shell ends.

The flag excludes every other `--secrets_*` option and disables agent
forwarding for the session. It refuses before any VM preparation when the
package is not installed. Default `aivm ssh` loads neither the adapter nor
this package; a subprocess test in AIVM checks this.

## Optional: ordinary HTTPS tools through the constrained profile

Add `"constrained_proxy": {"guest_port": PORT}` (1024–65535) to the spec to
also start the native `garrett-proxy` **inside the guest** as the
constrained-http translator (HP-6). It holds no credential. It accepts an
ordinary HTTPS request only if it is exactly one named operation of a public
copy of the policy (the host policy without `egress` and with a dummy
credential source), and sends that operation through the guest's
`garrett-client invoke`, so the host bridge authorizes every provider
effect on its own policy. The guest also receives:

- `proxy-ca.pem` and `proxy-bundle.pem` (the guest's roots plus that CA);
- `env`, which sets `HTTPS_PROXY` (with the translator's session token),
  `SSL_CERT_FILE`, `CURL_CA_BUNDLE` and `REQUESTS_CA_BUNDLE`.

The announcement then also carries `guest.env`. Tools that honour
`HTTPS_PROXY` work unchanged; they see only each operation's disclosure,
never full provider responses. `tests/test_native_session.py` drives stock
`curl` through it: an allowed read succeeds, an out-of-scope or unmatched
request never reaches the provider, and no guest file contains the
credential. The translator's lifetime lease is the session: closing the
session closes its stdin.

## Not yet covered

- A maintainer real-VM run of the SSH guest transport through `aivm ssh`.
  The real-KVM acceptance used the fixture driver, not this adapter.
- Revocation by AIVM's own machine store while the session is live. The
  Python adapter polls that store; this one does not. Revoking the guest
  subject in the **session authority** (`garrett-authority revoke --root
  WORKSPACE/host/authority`) does take effect on the next request, with no
  provider call (`tests/test_native_session.py`), as do registry changes
  (`tests/test_rust_identity_negative.py`).
- Guest mount/share reachability and aliases on a real VM (W8). Unregistered
  subjects, expired enrollments, re-enrolled certificates and expired
  capabilities are refused by the running bridge
  (`tests/test_rust_identity_negative.py`).
