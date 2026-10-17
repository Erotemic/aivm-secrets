# aivm-secrets (experimental)

An experimental Python broker for using host-held service credentials through
explicitly authorized operations. **Unaudited: not approved for production
credentials or unattended privileged use.** It is not a TPM or hardware identity
service and it is not a formally verified implementation.

This is the standalone project extracted from AIVM. It installs its own
`aivm-secrets` executable and does not require or bundle the AIVM VM manager.
The package version remains **0.2.0**; extraction does not change the wire
protocol or migrate existing authority, certificate, or OAuth vault state.

From a trusted host checkout that guests cannot modify:

```bash
umask 077
python3 -m venv .venv
.venv/bin/python -m pip install '.[tests]'
.venv/bin/python -m aivm_secrets --help
.venv/bin/python -m pytest -q
.venv/bin/python -m build
```

Tests use synthetic credentials and local test services. Independent Rust
backend tests skip unless their runners are explicitly configured;
those skips are not evidence of Python/Rust parity.

Start with the [operator guide](docs/source/secrets.rst),
[architecture and threat model](docs/planning/aivm-secrets-design.md),
[policy examples](docs/examples/), and
[assumption ledger](docs/planning/aivm-secrets-assumptions.json).
AIVM-specific commands in the operator guide require the separate AIVM checkout
and its existing experimental opt-in adapters.

The [extraction record](docs/extraction.md) explains the preserved authorship,
source commit, commit map, independent checks, and remaining integration work.
Original author and co-author attribution is retained in Git history:

```bash
git shortlog -sne aivm-extraction-base
git log --follow -- aivm_secrets/host/broker.py
```

The first [verified Rust freshness primitive](docs/verified-freshness.md) has
implementation-linked Lean proofs and scoped Python parity tests. It is an
independent development unit; the Python broker remains experimental and
unaudited, and full Rust broker/primitive-runner parity is still pending.

The [Rust Garrett implementation](docs/verified-garrett.md) now has signed and
encrypted surrogates, real TLS client/bridge executables, optional TPM signing
and creation-evidence verification, and independent Python parity tests. Lean
checks extracted issuance/opening controllers and a separate symbolic secrecy
model under explicit crypto, TLS, provider and key-custody conditions. The
[broader assurance campaign](docs/planning/aivm-secrets-garrett-verification.md)
still has open service, hardware and provider obligations; the whole broker
is not formally verified.

An explicit [Rust-owned provider profile](docs/verified-provider.md) now carries
`profile.read` from the authenticated client through credential custody and
pinned HTTPS to a typed public result, without a Python broker in that path.
The [composed request controller](docs/verified-composition.md) now joins
authentication, inner opening, authorization, acknowledged audit intent and
provider execution in the extracted Rust path. Its conditional proofs and
disclosure contract are separate from the general Python policy interpreter.
The [history layer](docs/verified-history.md) adds acknowledged issuance,
ideal signature-origin proofs and conditional correspondence between source
controller issuance and dispatch histories.
The [Rust certificate enrollment layer](docs/verified-enrollment.md) binds a
possession-checked CSR to explicit software approval or verified TPM evidence
before client signing. The [native authority path](docs/verified-garrett.md#native-authority-and-live-admission)
now initializes a Python-compatible private store, enrolls and renews clients,
records TPM assurance, and coordinates revocation with native provider use.
Native issuer/server/root rotation, explicit trust-transaction recovery and
acknowledged token issuance to protected host files are implemented too.
The native OAuth vault now preserves Python schema-2 ciphertext, refreshes through
a pinned HTTPS origin and holds revocable credential leases through provider use.
Extracted Lean contracts check durable quarantine before refresh and persistence
before returning a successor. Native host-only PKCE login now binds its loopback
callback before emitting the browser URL, exchanges one accepted code and installs
the grant directly into the encrypted vault. Its callback/lifecycle guards have
extracted proofs. A new native `manifest-https-v1` backend executes host-selected
operations with typed parameters, checked facts, bodies, pagination and fixed
GraphQL reads. Its [extracted recursive filter](docs/verified-disclosure.md) has
conditional Lean selection and noninterference proofs. It requires an explicit
typed response disclosure contract and uses extracted parameter and
operation/write guards. Client aliases, command resolvers, approvals/delegation,
JSON/I/O adapter refinement and whole-service verification remain open.

The native client also supports [software key/CSR bootstrap and recovery](docs/verified-client-material.md)
with explicit software mode, protected no-replace publication and an extracted
controller for ordered acknowledgement and uncertain outcomes.
