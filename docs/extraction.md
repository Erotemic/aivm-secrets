# Standalone extraction record

The maintainer authorized the initial repository extraction on **2026-10-16**.
This repository is the independent development starting point for the
experimental, unaudited `aivm-secrets` project. Publication, security approval,
and retirement of AIVM's co-located copy remain separate decisions.

## Source and attribution

The source is `Erotemic/aivm`, branch `dev/0.6.2`, commit
`27bc4d2afa8ded6e45ab47517dba7294724260dc`. The source repository's history
was left intact. A disposable clone was filtered with `git-filter-repo 2.47.0`,
using the paths in [history-paths.txt](../dev/port/history-paths.txt) and
`--preserve-commit-hashes`. That flag preserves literal references in commit
messages; the actual commit IDs change because their trees and parents change.

**46 commits** survive, including their original author and committer names,
email addresses, timestamps, full messages, and `Co-authored-by:` trailers.
Those fields were compared byte for byte with the source Git objects. Original
signatures cannot attest to rewritten commits; the source remains authoritative
for original signatures and hashes. Attribution is preserved as recorded,
including generic identities already present in the source.

- [source.json](../dev/port/source.json) pins the source, inventories external
  assurance references, and lists integration tests retained in AIVM.
- [aivm-commit-map.txt](../dev/port/aivm-commit-map.txt) maps source commit IDs
  to extracted commit IDs. All-zero destinations mean the commit was pruned.
- The annotated tag `aivm-extraction-base` marks the filtered tree before
  standalone setup. Package metadata and README were then moved to the root
  in an ordinary new commit, so Git can follow their history.

With the original source repository available, independently verify attribution:

```bash
python3 dev/port/verify_history.py /path/to/aivm
git shortlog -sne aivm-extraction-base
git log --follow -- aivm_secrets/host/broker.py
```

## What the initial port includes

The Python package, version **0.2.0**, retains its import name, executable,
process interfaces, wire versions, and production implementation. The port
brings standalone tests, synthetic providers, conformance vectors, policy
examples, design documents, operator documentation, and the Apache-2.0 license.
Root packaging builds an independent wheel and source archive; source archives
also contain tests, documentation, vectors, and extraction metadata.

The standalone suite uses its own fixtures and dependencies. It neither installs
nor imports AIVM. Tests that exercise libvirt, the guest bootstrap helper, the
AIVM launcher, and AIVM-only packaging stay maintained in AIVM. Their historical
versions remain in this repository's extraction tag. Two AIVM source-inspection
checks and the launcher/bridge timeout comparison also stay in the original
mixed modules. The bridge child-process cleanup test remains here with an
explicit ten-second standalone shutdown budget.

The assumption ledger retains all assumptions. References to AIVM-owned modules
and tests now link to the exact source commit. Standalone tests validate local
evidence paths and the inventory of external references; they do **not** claim
to execute or revalidate external integration tests. Existing Rust-runner skips
continue to mean that independent implementations are unavailable.

Tests create private fixtures under a session-local umask, preserving production
ownership checks. Set `umask 077` before creating a development environment:
the broker rejects installations and state writable by an untrusted group.

The [operator guide](source/secrets.rst) and imported design plans include AIVM
integration examples and historical validation reports. Those require a
separately installed compatible AIVM checkout and do not establish new standalone
VM or provider validation. Start with root README commands for standalone use.

## Initial validation

On Python **3.12.3**, the offline suite passed with **1,861 passed and 10
skipped**, including the security mutation gate (254.25 seconds). The ten
skips require independent Rust runners that are not implemented. The wheel and
source archive built and passed `twine check`; a fresh environment installed the
source archive without AIVM and exercised isolated policy validation and identity
CLI help. Git integrity and all 46 retained commits' attribution were verified.
The committed CI matrix covers Python 3.11–3.14; remote CI has not run yet.

## Remaining cutover and release work

1. Review the extracted repository and choose its hosted remote and release
   ownership. No remote or publishing workflow is configured by this port.
2. Freeze and review the portable process/CLI contract, identity fact provenance,
   authority formats, outcome/exit semantics, and version compatibility policy.
   This port preserves existing interfaces rather than declaring a new freeze.
3. Decide ownership and deployment of the AIVM guest identity helper, and whether
   the existing experimental adapters remain supported. Define a small explicit
   cross-project integration matrix pinned to selected versions or commits.
4. Change AIVM's development installation instructions and CI to consume the
   independent repository, then remove its duplicate package and portable tests
   in a coordinated follow-up. AIVM currently retains its working copy and CI.
   Do not add a mandatory dependency or an extra on an unpublished package.
5. Review existing authority, certificate, and OAuth-vault compatibility before
   any migration. No live credentials or stored state were copied or migrated.
6. Complete the separate security and release gates in the
   [boundary plan](planning/aivm-secrets-repository-boundary.md). Successful
   extraction and tests do not imply an audit, formal proof, or production
   approval. No release automation is enabled here.
