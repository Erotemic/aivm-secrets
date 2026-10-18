# Optional native coordination authority

`garrett-coordinator` serves the existing coordination protocol using Rust,
mTLS and one local SQLite database. Python and Rust brokers can use it with
their existing coordinator configurations. The Python authority remains an
independent reference implementation. No broker silently starts this service
or changes its selected coordinator.

The service has no provider credential or capability input. It decides whether
an authenticated host member is active, reserves principal-scoped write keys,
and records completion. Only configured operator certificate fingerprints may
activate/revoke principals or inspect their status.

## Run the native service

Build the optional server explicitly. SQLite is bundled by the optional
`rusqlite` dependency; an ordinary native broker build enables neither it nor
the server binary. Python/AIVM packaging and VM provisioning remain independent.

```bash
cargo +nightly-2026-09-17 build --manifest-path rust/Cargo.toml \
    --release --bin garrett-coordinator --features coordinator-server --locked
umask 077
rust/target/release/garrett-coordinator init --directory /absolute/private/coordination
rust/target/release/garrett-coordinator serve --config /absolute/private/server.json
```

The existing parent directory must be owned and private. Initialization requires
a new directory and never replaces an existing authority. A failed initialization
may leave its coordinates for explicit inspection; it is not silently retried or
repaired. `serve` prints one host-only JSON readiness record containing its actual
listen address, then serves until stopped. No service is installed or enabled.

The private configuration has exactly these fields (replace the example paths
and fingerprint before starting):

```json
{
  "schema": 1,
  "listen": "127.0.0.1:9443",
  "directory": "/absolute/private/coordination",
  "server_certificate_file": "/absolute/private/server.pem",
  "server_key_file": "/absolute/private/server.key",
  "client_ca_file": "/absolute/private/client-ca.pem",
  "operator_fingerprints": ["REPLACE_WITH_LOWERCASE_64_HEX_CERTIFICATE_SHA256"]
}
```

The address is an explicit IP/port; use port zero for a local test. Choose a
certificate whose verified DNS name matches the clients' configured host. The
service requires TLS 1.3 and a client certificate under the selected CA. Session
resumption and early data are disabled. A CA-valid certificate alone does not
authorize membership or administration.

Coordinator identities are **lowercase hex SHA-256 hashes of complete client
certificate DER**, matching Python. Garrett JWT confirmation uses base64url
thumbprints; those strings are not interchangeable. Certificate renewal changes
a coordinator certificate identity even when its public key stays the same.
Member sets and operator configuration are explicit host administration, not
an automatic enrollment/renewal mechanism.

Existing Python `CoordinationClient`/CLI tools can administer this service. A
host operator can also inspect the wire operation with ordinary tools:

```bash
curl --tlsv1.3 --cacert /absolute/private/server-ca.pem \
    --cert /absolute/private/operator.pem --key /absolute/private/operator.key \
    --header 'Content-Type: application/json' --data-binary @request.json \
    https://localhost:9443/v1/coordinate
```

For example, `request.json` can contain
`{"action":"activate","name":"team","members":["MEMBER_CERTIFICATE_SHA256_HEX"]}`.
Use the actual 64-character member hash. The protocol replies with HTTP 200 and
a JSON `ok` verdict; HTTP status alone is not authorization. `check`, `reserve`
and `finish` are member operations. `activate`, `revoke` and `status` require a
configured operator. Requests and replies never contain private keys.

## Durable behavior and interoperability

The database retains Python's `principals` and `writes` schema. Each decision
reads the stored row in a fresh transaction. The native process holds one
mutex-protected connection rather than an admission cache. Mutation transactions
use SQLite IMMEDIATE locking, WAL and synchronous FULL; the
[transaction API](https://docs.rs/rusqlite/0.40.2/rusqlite/struct.Connection.html#method.transaction_with_behavior)
requires explicit commit. No positive reply leaves the ledger handler before
that commit acknowledges. Read decisions use a transaction snapshot. Operations
already admitted before a revocation may finish after it.

- Registration creates an absent principal. An existing name cannot be
  reactivated or have its member set silently replaced.
- Revocation creates a terminal tombstone even for a never-registered name.
  Every later member check denies it; recovery requires a deliberately new name.
- A reservation is keyed by principal and derived retry key. Once present, that
  key remains spent whether its digest matches, differs or is already completed.
- Finishing requires the stored digest. Repeating a matching finish is harmless;
  it does not make the key reusable. No failed/uncertain exchange auto-retries.
- Unavailable storage, unsafe paths or poisoned native state fail closed.
  Storage failures use the fixed `audit_failed` code, without SQL diagnostics.

The directory is opened through held no-symlink descriptors. SQLite's VFS needs
an ordinary path: the adapter resolves/reopens the held directory and compares
its inode, then enables SQLite's no-symlink open flag and verifies private,
regular, single-link database/sidecar files. This is not a custom proved
`openat` SQLite VFS. Host-controlled path/inode stability remains an assumption.

Run **one trusted local authority**. Do not put the DB on a network filesystem,
replicate/copy its file for multiple authorities, restore a prior snapshot, or
replace its inode while serving. These operations can invalidate terminal
revocation and key uniqueness. This implementation supplies no consensus or
anti-rollback witness. Stop the authority before an explicitly reviewed move.

## Checked Rust/Lean scope

`proofs/GarrettCoordinatorAuthority.lean` checks the extracted production core:
exact peer matching, exhaustive typed action-to-role authorization, absent-only activation,
revocation, reservation and completion decisions. It also proves, over histories
of those actual successful decisions plus unchanged rows:

- A tombstone remains a tombstone, and no later peer is admitted for that name.
- A spent key remains present, and no later reservation succeeds for that key.
- Matching completion preserves the digest and has an exact successful return.
- Operators cannot use check/reserve/finish without active principal membership;
  members cannot activate/revoke/inspect status without configured operator authority.
- Every member action remains denied after a tombstone under the modeled history.
- Positive authorization witnesses cover every typed action. They concern the
  role gate; activation/reservation can still be refused by the later row decision.

These are **pure decision and modeled committed-history proofs**. They do not
prove SQLite statements, transaction isolation/durability, row/JSON conversion,
wire-string-to-typed-action parsing, fingerprint derivation, TLS authentication, native commit/reply
placement or whole-service mediation. The source guards, compiler paths and
runtime tests provide separate evidence for those adapters; they are not a
substitute for a native trace-refinement proof. This service is experimental
and unaudited.

## Runtime and regression gates

`tests/test_rust_coordinator_authority.py` runs real native authority processes
with independent Python TLS clients. The frozen
`tests/secrets_vectors/coordination/authority-v1.jsonl` corpus checks exact
replies and durable rows in both implementations. Cases cover roles, active
members, wrong peers, duplicate/different-digest writes, preemptive/repeated
revocation, malformed typed requests, HTTP framing, restarts, cross-backend
storage, unsafe paths and missing client certificates. A 144-case cross-backend
matrix exercises all six actions across absent/active/revoked principals,
ordinary members, outsiders, operators and operators explicitly enrolled as
members; every denied call must leave both durable tables unchanged. Broker workflows run
against both authority backends in `tests/test_rust_coordination.py`.

This port reproduced and fixed Python accepting duplicate length/type fields
and an empty Transfer-Encoding field, returning an internal error for unhashable
member values, and blocking legitimate requests behind an anonymous TLS stall.
Handshakes now occur inside bounded Python worker slots. Native workers also
have a fixed five-second socket deadline. Resource bounds and unsupported HTTP
forms can still differ; full all-input wire/core parity is not claimed.

```bash
python dev/verification/garrett.py record
python dev/verification/garrett.py mutate --mutation-filter '^coordinator (authority|dispatch) '
python dev/verification/system.py --proofs --full-tests --call-linkage
python dev/verification/specialized_calls.py --profile coordinator
```

The filtered campaign targets only the new authority decisions. Compiler paths
start at the named compiled connection handler; they do not prove accept-loop
reachability, admission dominance or complete I/O mediation. TPM, VM and live
provider evidence remain separate from this local service.

The [typed authorization validation record](../dev/validation/2026-10-18-coordinator-dispatch.json)
binds source `078ef2d`, 2,472 portable tests with zero skips, 250 required workflow
tests in each build mode, 299 audited Garrett obligations and four newly
re-extracted role-dispatch mutations. It preserves both compiler profiles and
keeps their mediation obligations open. The earlier
[authority port record](../dev/validation/2026-10-18-coordinator-authority.json)
retains the original cross-backend port and reproduced Python regressions.
