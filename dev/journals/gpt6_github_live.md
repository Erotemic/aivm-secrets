# 2026-10-21 — OUT-3 read-only live GitHub fixture

Target is the existing `Erotemic/aivm-secrets` repository. User supplied
permission to use it for read-only validation, not permission to create
resources or to access a broad host credential. The native GitHub PR preset
cannot assume an existing PR in this repository, so the opted-in fixture
uses the service-neutral schema-2 native manifest: authenticated `/user`,
repository metadata, README metadata, and one explicitly denied issue POST.

The test reuses the passing OUT-2 real KVM client enrollment, SSH Unix-socket
forward and mTLS client. A dedicated operator-provisioned fine-grained PAT
is an external input stored in a private host file, never copied into the VM.
Host OS CA bundle and one DNS-resolved GitHub IPv4 destination supply the
explicit external TLS/routing assumptions. The broker is configured
`writes=deny`; host audit is checked for additional dispatch records after
negative actions. GitHub-side raw credentialed request accounting is not
available, so do not claim direct provider-side observation or exhaustive
read noninterference.

Source changes are an opt-in operator script, portable tests, and handoff
status/documentation. No native Rust behavior, Lean theorem, AIVM configuration
or synthetic OUT-2 test behavior is changed. The real GitHub command must be
run by the operator after token provisioning; authoring checks are not a
substitute for that result.

## 2026-10-21 21:50:51 -0400

The operator's first real KVM/GitHub attempt reached revocation after three
authorized GitHub reads and the named out-of-scope/write denial checks. It
failed with `revoked VM guest was still able to read GitHub identity`. Code
inspection found the exact fixture defect: `garrett-client invoke` returns a
public `{"ok":false,"error":...}` frame on stdout and exits nonzero for
identity denial, whereas the previous `gh` alias tests returned no stdout.
The fixture incorrectly treated *any* stdout as a successful provider read.
This failure therefore does not establish a successful post-revocation read.

The fix requires the host authority's native pre-revocation and post-revocation
status to show the correct `live-guest` epoch transition and inactive state,
requires an exact, public identity-denial frame from the same guest capability
(`invalid_capability` or `revoked`), and independently asserts the native host
provider-audit dispatch count is unchanged. Test coverage rejects successful
responses, policy-only denials, malformed/unexpected fields and nonpersistent
revocation. No Rust, credential, VM, firewall, Lean or provider policy changes.
The operator must rerun the opt-in live test; these portable tests are not
evidence that the corrected check passed on the real VM.
