# aivm-secrets

A host-side credential broker for code running in a virtual machine. The
code in the VM, typically a coding agent, asks for named operations such as
"read this pull request". The broker checks each request against a policy,
calls the provider with a credential that stays on the host, and returns only
the fields the policy selects. The guest never holds the credential.

The project has two implementations of the same protocol:

- a **native Rust** broker (`rust/`), whose decision logic is extracted with
  [Aeneas](https://github.com/AeneasVerif/aeneas) and proved in Lean
  (`proofs/`);
- a **Python reference** (`aivm_secrets/`), which defines the protocol and
  carries features that have not been ported yet.

It works on its own or with [AIVM](https://github.com/Erotemic/aivm), which
can start a broker session for a VM. AIVM never requires this package.

## How a request flows

```text
 guest VM                       trusted host
 ─────────                      ──────────────────────────────────────────
 agent ─► garrett-client ══mTLS══► garrett-bridge ─► policy check
                                         │            audit record (synced)
                                         │            credential from custody
                                         ▼
                                   provider HTTPS ◄── exact request bytes
                                         │
 agent ◄── selected fields ◄═════════════┘  (or one of 17 fixed denials)
```

The guest proves who it is with a client certificate issued by
`garrett-authority`. The host decides what each identity may do. Every
provider call is preceded by an audit record that has been written and
synced. Revoking a guest stops all later calls.

## Properties

✅ means it exists and is checked by the evidence named. ⬜ means it is on
the [plan](docs/planning/aivm-secrets-active-work.md).

### Features

- ✅ Named operations from a host manifest (`manifest-https-v1`): typed
  arguments, fixed destinations, selected response fields, pagination and
  fixed GraphQL reads
- ✅ Guest identity: certificate enrollment, renewal, revocation and key
  rotation; optional TPM-backed guest keys
- ✅ Durable audit log; hash-chain verification for both brokers
  (`aivm-secrets audit-verify`, `audit-verify --native`)
- ✅ OAuth credential vault with refresh and host-only PKCE login (native)
- ✅ Exact-write approval: a write waits until the operator approves its exact
  bytes once (`aivm-secrets approve`)
- ✅ Optional multi-host coordinator for shared revocation and write
  reservations (`garrett-coordinator`, opt-in build feature)
- ✅ A read-only bridge (`garrett-bridge-read-only`) that refuses any
  configuration outside the proved read profile ([release guide](docs/release-read-only.md),
  [protocol v1](docs/protocol-v1.md))
- ✅ Optional HTTPS proxy profiles for stock tools such as `gh` and `curl`:
  `constrained-http` (requests become named operations) and
  `credential-substitution` (credential added at the proxy; see
  [its limits](docs/https-proxy-profile.md))
- ⬜ Budgets and delegation in the native broker (Python only today)

### Proved in Lean, about the Rust code that runs

These hold for the native read profile (`manifest-https-v1`, writes denied,
one guest session at a time). The [proof tour](docs/assurance/native-read-proof-tour.md)
explains each one in plain language.

- ✅ Every provider call of a completed request was authorized at that moment,
  had a synced audit record first, and was bound to the requesting identity.
  This assumes no other native code writes the credential (see the next
  section)
- ✅ The provider request bytes are exactly the encoder's output for the
  chosen route. Header and request-line injection are impossible within the
  stated size bounds
- ✅ A successful reply to the guest is exactly the encoding of the selected
  fields, and the credential is not in it. A denial is one of 17 fixed lines
- ✅ Noninterference: a guest that adapts each request to earlier replies sees
  the same replies in two worlds that agree on the selected data, the
  pagination row count, the status class and the public failure code
- ✅ Base64url text in a token is accepted only if the extracted encoder,
  proved injective, reproduces it exactly, so each accepted token decodes to
  exactly one byte string
- ✅ Writes: a completed write had a single-use approval for its exact digest
- ✅ Proxy substitution: the credential is placed only in the upstream request
  and never appears in a released response
- ✅ A guest that renounces its grant is refused on every later request
- ✅ An accepted `constrained-http` request is the host encoding of exactly
  one named operation and one set of arguments, when path values are single
  segments (HP-6; the condition is necessary)
- ✅ Across every history of enrollment, refresh, revocation and crashes,
  each request sent had a current identity and credential lease, and a
  revoked session never sends again (a model over the extracted lease check)
- ✅ An OAuth login exchanges its authorization code at most once, and only
  after a callback bound to its state, issuer and time window
- ⬜ No other native path writes the credential (`NATIVE-SINK-01`). The
  credential type is sealed at compile time, its seven readers are pinned,
  and a whole-process `strace` run shows no credential bytes in any write and
  no destination but the provider. What remains is a short contract on those
  readers for a reviewer to accept
- ✅ An exactly approved write through a real VM: held until the host
  approves its exact digest, sent once, never reusable
- ⬜ Provider-side write semantics and uncertain outcomes across sessions
  without a coordinator

- ✅ An axiom audit of all 1,444 theorems: each rests only on Lean's three
  standard axioms, with no `sorry` and no unproved assumption about the
  extracted Rust ([audit](docs/assurance/axiom-audit.md))

### Tested end to end

- ✅ Offline operator and guest with the real native binaries
  (`dev/offline_native_guest.py`)
- ✅ Real KVM guest: approved reads, denied write, revocation, foreign and
  tampered identities, host TCP canary, mount inventory, socket reconnect
  ([details](docs/aivm-vm-native-acceptance.md))
- ✅ Live GitHub, read-only, from a real VM: three approved reads, an
  out-of-scope repository and a write refused, revocation
  ([details](docs/aivm-github-live-readonly-acceptance.md))
- ✅ A second, synthetic provider with different authentication runs through
  the same generic path with no provider-specific Rust
- ✅ Both proxy profiles in a real VM, with AIVM's direct internet access on
  and off; re-enrolled certificates refused; a search of every guest share
  (as guest root) never reaches the host's custody files
  ([run record](dev/validation/2026-10-24-local-vm-acceptance.json))
- ✅ A simulated agent inside the VM tries 21 ways to get more than it was
  granted (path and header injection, other repositories, malformed and
  oversized arguments, unlisted operations, raw bytes and TLS without a
  certificate on the broker socket). Every one is refused, with no provider
  traffic beyond its two allowed reads. A root search of every file and
  process in the guest then finds no trace of the credential

### Review

- ⬜ Independent review of the read claim (NR-5) and of a read-only release
  profile (OUT-5)

### Trusted, not proved

The proofs take these as given: the cryptography and TLS libraries (`ring`,
`rustls`), the Rust compiler, the OS and VM isolation, the clock, filesystem
durability, and `serde_json` parsing of provider bodies. Each is an entry in
the [assumption ledger](docs/planning/aivm-secrets-assumptions.json), with
its removal path in the [assumption roadmap](docs/planning/aivm-secrets-assumption-roadmap.md).

## Getting started

Python reference and tests, from a host checkout that guests cannot modify:

```bash
umask 077
python3 -m venv .venv
.venv/bin/python -m pip install '.[tests]'
.venv/bin/python -m pytest -q
```

Native binaries and the offline demo (the toolchain is pinned in
`rust/rust-toolchain.toml`):

```bash
cargo build --manifest-path rust/Cargo.toml --bins
python dev/offline_native_guest.py
```

The full check builds the native code, runs every test with no skips allowed,
and compiles the proofs. It needs the Lean and Aeneas toolchains:

```bash
python dev/verification/system.py --proofs --full-tests
```

Tests use synthetic credentials and local HTTPS services only.

## Documentation

- [Operator guide](docs/source/secrets.rst) and [policy examples](docs/examples/)
- [Design and threat model](docs/planning/aivm-secrets-design.md)
- [Plan](docs/planning/aivm-secrets-active-work.md) and
  [outcome gates](docs/planning/aivm-secrets-product-roadmap.md)
- [Proof tour](docs/assurance/native-read-proof-tour.md) and
  [claim-to-evidence matrix](docs/assurance/claim-evidence-matrix.md)
- [Assurance by configuration](docs/assurance-profiles.md)
- [Contributor rules](AGENTS.md)

## History

This repository was extracted from AIVM with its history intact; see the
[extraction record](docs/extraction.md). The package version is 0.2.0.

```bash
git shortlog -sne aivm-extraction-base
git log --follow -- aivm_secrets/host/broker.py
```
