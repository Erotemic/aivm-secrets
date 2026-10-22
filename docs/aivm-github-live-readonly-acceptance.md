# OUT-3: real GitHub read-only acceptance on `aivm-2404`

**Status (2026-10-21): live run reached the post-revocation check, but
acceptance remains pending a rerun after correcting the `invoke` denial-frame
assertion.** Three authorized GitHub reads and the preceding negative checks
completed in the operator's first run. Its final assertion was faulty: native
`invoke` prints a structured `{"ok":false,"error":...}` frame on stdout with
exit status 1 when identity admission is rejected; stdout is not proof of a
successful read. The fixed fixture requires an identity-denial code, a
persistently inactive native authority enrollment with an incremented epoch,
and no additional provider dispatch. The user has not yet rerun these fixed
checks on the real VM.

This is the *real provider* follow-up to the user-confirmed OUT-2 adversarial KVM
acceptance in [the synthetic provider test](aivm-vm-native-acceptance.md).
It is not a CI test, a whole-service proof, or the optional production AIVM
adapter. This fixture uses **the existing `Erotemic/aivm-secrets` repository**;
no test repository, PR or issue needs to be created. The target has no assumed
PR number or current branch commit hash.

The entry point is [`dev/aivm_github_live_acceptance.py`](../dev/aivm_github_live_acceptance.py).
It operates from the host with the production native Rust authority/broker and
runs the native `garrett-client` inside a real managed KVM guest via a temporary
SSH-forwarded Unix application socket plus native mTLS. No token, credential
file, host authority root or host provider-socket mount is sent to the guest.
The guest creates its own private key and supplies only a CSR to the host.

## Host-side operator setup (explicit live test)

Create a short-lived, **fine-grained personal access token** at
[GitHub token settings](https://github.com/settings/personal-access-tokens/new).
Select the `Erotemic` resource owner and **only the `aivm-secrets`
repository**, with **Contents: read-only** and no write permissions.
Repository metadata read access is implicit; `/user` works with fine-grained
PATs without additional account permissions. Do not use an existing broad
`gh auth token` or copy a credential into the checkout. Expire/delete the
fixture token after testing. A public repository alone would also be readable
anonymously; this harness additionally reads authenticated `/user` so that
credential substitution is not inferred from public GET success.

Enter the token on **`toothbrush`** without echoing it or putting it in shell
history. The snippet creates a new file only, with mode 0600 under a private
host directory. Do not paste the token into chat, Git, test logs or a shared
AIVM attachment.

```bash
cd ~/code/aivm-secrets
install -d -m 700 "$HOME/.config/aivm-secrets"
python - <<'PY'
import getpass
import os
from pathlib import Path

path = Path.home() / '.config/aivm-secrets/github-readonly.token'
value = getpass.getpass('Paste the dedicated read-only GitHub token (hidden): ')
if not 16 <= len(value) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in value):
    raise SystemExit('Token must be nonwhitespace printable ASCII; no file written')
os.umask(0o077)
with path.open('xb') as f:
    f.write(value.encode('ascii'))
print('Created a private host-only GitHub credential file')
PY
```

If the file already exists, the write refuses instead of silently replacing
it. Inspect/delete the old token yourself before provisioning another.

Build native binaries, run portable guards, then execute the *explicitly
opted-in* live fixture:

```bash
cd ~/code/aivm-secrets
cargo +nightly-2026-09-17 build --locked --manifest-path rust/Cargo.toml --bins
python -m pytest -q tests/test_aivm_github_live_acceptance.py tests/test_aivm_vm_acceptance.py

RUN="/tmp/garrett-github-live-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python dev/aivm_github_live_acceptance.py \
  --live-github --vm aivm-2404 --workspace "$RUN" && \
python -m json.tool "$RUN/summary.json"
```

The token file defaults to `$HOME/.config/aivm-secrets/github-readonly.token`.
It is never copied into the workspace. An alternate file may be selected with
`--token-file` if kept private outside the repository and shared VM folders.
Use a fresh host workspace under `/tmp`, not the group-writable source tree.
The successful result is *evidence reported by this local run*, not evidence
that the test has already happened when this document was authored.

## Exact allowlist and evidence

- **`account.probe`:** Native GET `https://api.github.com/user` with the
  host-injected bearer token. The guest receives **only**
  `authenticatedUserId` (integer). Anonymous requests cannot pass this
  authentication check. The harness records only a boolean in its summary.
- **`repo.view`:** GET `/repos/{owner}/{repo}` with owner restricted to
  `Erotemic` and repo restricted to `aivm-secrets`. The guest receives only
  `fullName`, `defaultBranch` and `private`. The expected repository is public.
- **`repo.readme`:** GET `/repos/{owner}/{repo}/readme`, with the same fixed
  owner/repo. The guest receives only `path`, `sha` and `size` (not raw README
  content or unselected upstream fields).
- **`repo.issue`:** A declared POST `/repos/{owner}/{repo}/issues` that is
  *always denied* under the native broker's immutable fixture setting
  `writes=deny`. The harness tests it with a title but must not create an
  issue. An out-of-scope `repo.view` for `Erotemic/aivm` is also denied.
- **Revocation:** After the successful reads, the host native authority
  revokes `live-guest`. The harness compares the returned revocation state
  with a fresh authority status read and requires an incremented epoch and
  inactive enrollment. Its next authenticated `invoke` must exit nonzero with
  a strict public identity-denial frame (`invalid_capability` or `revoked`),
  with no selected result and no new host audit dispatch. Unlike the native
  `gh` alias, a denied `invoke` prints JSON to stdout; an empty-stdout
  assertion is incorrect.

The host pins one trusted-DNS-resolved, reachable public IPv4 address for
`api.github.com` in **both** the manifest and native provider configuration.
The native TLS writer still verifies `api.github.com` using TLS 1.3 and a
private copy of the Ubuntu system CA bundle. This is a pinned **IP/hostname
route with ordinary CA trust**, not a GitHub leaf-certificate pin or proof of
DNS infrastructure security. A host without direct HTTPS or system CA roots
may fail; do not disable verification or route through an unreviewed proxy.
The GitHub REST version is `2026-03-10`.

The harness rejects token files that are symlinks, hardlinked, group/world
accessible, malformed, or inside the repository. The Rust private-file guard
also checks path ancestry. Neither harness nor native binary is permitted to
print token bytes; the resulting JSON and host audit must not contain the
bearer token or signed surrogate. The test reads audit metadata for the three
allowed dispatches and asserts that denied, out-of-scope and revoked requests
add no dispatch record. Only three **approved** calls are expected.

**Important evidence distinction:** Unlike the synthetic OUT-2 provider, we
do not control GitHub servers or receive a provider-side request transcript.
Therefore `provider_requests_directly_observed` is **false**. Real GitHub
success and native host audit are complementary witnesses, **not** proof of
all downstream HTTP effect timing or exhaustive network mediation. Passing
also does not show that the fine-grained token has no permissions outside the
operator-selected repository; that scope is created/reviewed in GitHub's UI.

The VM may have general public-Internet egress; this harness does not claim to
block every outbound connection. Its narrower claim is that this bounded
native client invokes the named broker operations while the actual provider
credential remains on the host. Other guest mounts, aliases, privileged guest
access, and whole-service secrecy remain bounded by the W0 assumptions and
independent OUT-2 security analysis.

## Diagnosing failures without exposing a token

- An absent token file: provision the dedicated private file above. Do not
  point the harness to `.tools`, your Git checkout, or the guest filesystem.
- A native `unsafe_file`: inspect token and workspace ancestor modes; do not
  loosen the Rust trusted-path checks.
- A `VM_IP_UNKNOWN`: run `aivm vm wait_ip` on the host, then retry the new run.
- A GitHub `/user` error: review fine-grained PAT validity/expiry/repository
  selection. Do not print token values, native stderr or full GitHub replies.
- DNS/TLS/provider error: confirm host direct outbound 443 and system CA
  installation. Do not set `SSL_CERT_FILE` to an untrusted authority or disable
  hostname verification.
- A failed denied-write/out-of-scope/audit assertion: **retain** the failed
  workspace privately for inspection; do not weaken a guard or retry with a
  broad token.
- A revocation failure: the native `invoke` emits an error JSON object to
  stdout on rejected admission and exits 1. The harness checks this denial
  frame, the persisted authority status, and unchanged host dispatch count.
  Do not treat mere stdout presence as a successful GitHub read, and do not
  classify a transport failure or arbitrary policy rejection as proof of
  identity revocation.

After testing, revoke/delete the disposable token on GitHub and remove the
private host token file when it is no longer needed.

The [product roadmap](planning/aivm-secrets-product-roadmap.md) and
[active queue](planning/aivm-secrets-active-work.md) track OUT-3 separately
from the more demanding NR-2/3/4 proof campaign and OUT-4 authorized writes.
