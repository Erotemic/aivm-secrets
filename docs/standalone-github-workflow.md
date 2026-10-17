# W1: standalone GitHub-like credential workflow

**Status:** W1 local test implementation for snapshot `28e466d` with the W0
planning overlay. This is not a production deployment or a confidentiality
proof. It uses only fabricated credentials, a locally generated TLS CA, and
fixed PR data. No AIVM, VM, live GitHub API, or externally stored token is used.

Run from the `aivm-secrets` checkout after installing test dependencies:

```bash
python -m pip install -e '.[tests]'
python -m pytest -q tests/test_secrets_w1_github_workflow.py
```

The installed `aivm-secrets` entry point is exercised through isolated Python
subprocesses (`python -I -m aivm_secrets`), not a mock of the broker API.
The HTTPS test server is a real loopback TLS server with a host-chosen pinned
address and test trust anchor. It records the request method, path, selected
headers and request body. The broker resolves a synthetic bearer token from a
private file and performs its own verified TLS egress; the guest never receives
that file path through its CLI inputs.

## Named W1 scenario: `synthetic-github-pr-read-v1`

Shared values are in `tests/secrets_github_scenario.py`, deliberately
separated from `tests/test_secrets_w1_github_workflow.py` so W2 can reuse the
provider traffic and intent without presuming Rust/Python protocol parity.

- **Allowed scope:** repository `TauCetiProject/TauCeti`, PR 13861, author
  `Erotemic`, head repository `Erotemic/TauCeti`, checked head SHA of forty
  `a` characters. The policy is the real schema-1 GitHub preset expanded to a
  schema-2 manifest, with its HTTPS host, CA/pin and credential source
  replaced by locally controlled test inputs.
- **Positive workflow:** a subprocess guest reads PR metadata, uses the
  GitHub-shaped alias to select metadata fields and read a diff, and reads
  check runs bound to the preflight-checked head SHA. Assertions compare exact
  guest output and the **eight** HTTPS requests received by the provider,
  including the expected preflight/final Accept headers and bearer credential.
- **Denied workflow:** another PR, an explicitly declared but operator-denied
  write, unknown operation/endpoint, an extra injected URL argument, and an
  unsupported `gh api` command. None of these sends provider traffic.
- **Provider-controlled failures:** echoing the *literal* bearer credential in
  an allowed diff fails before a successful guest reply; a PR with the wrong
  head repository fails its fact check after metadata preflight but before
  final request dispatch. These tests do **not** establish general prevention
  of encoded, fragmented or inferred secret disclosures.
- **Session lifecycle:** host-side revocation and time-based expiry reject
  reuse of the credentialed capability; provider traffic does not grow after
  either denial. Host audit is hash-chain-verified, contains no literal token
  or sealed capability, and closes on session teardown. The transient Unix
  socket and capability file are removed.

All assertions run against the real Python policy engine and local HTTPS
executor. The tests do **not** establish that a separate OS user, VM or
container cannot access host files, that arbitrary provider outputs are safe
to declassify, or that the Rust native service already implements this
workflow. Those are distinct W2/W3/W6/W8 work items. This local exercise also
cannot establish live GitHub API compatibility; that is W7's opt-in check.

## W2 handoff

Reproduce the **same operator intent** with native Rust: pinned HTTPS provider,
allowlisted PR, checked metadata and head commit, read/diff/checks, and the
same invalid-request/unauthorized-request variants. Where Rust only supports
typed disclosure and lacks `gh` aliases or one-shot write approvals, report
the differences explicitly. Do not invoke or fall back to Python from Rust.
The Python test's guest reply formats are evidence of Python behavior, not a
contract requiring Rust to emit byte-identical output.
