# Python Garrett: durable coordination, rolling credentials, keyed writes

**Scope:** the independent Python reference implementation. This work adds
opt-in cross-host decisions; it does not make an ordinary uncoordinated
session cross-host-safe, replicate a vault, or prove the Python interpreter.

## 1. One durable revocation and write-reservation authority

`aivm_secrets.identity.coordination` has one trusted authority and many
mutually authenticated host clients. The authority alone owns a local SQLite
WAL database (`PRAGMA synchronous=FULL`, `BEGIN IMMEDIATE` for revocation and
reservations). **Do not** place this database on NFS, a VM shared mount, or
copy a writable database to each host. A successful SQLite COMMIT is the
modeled linearization point; local storage, fsync and backup discipline are
operational assumptions, not formally verified properties.

- Every principal is explicitly activated by an operator with the SHA-256
  fingerprints of the *host clients' DER TLS certificates*. A known-but-
  unauthorized peer cannot check, reserve or finish. Enrollment is not implied
  by a CA-signed certificate.
- The operator certificate fingerprint is separately pinned for
  `activate`, `revoke` and `status`. Ordinary registered host certificates do
  not permit administrative verbs.
- Revocation is a **terminal tombstone** for a principal name, durable across
  coordinator restarts. It may be committed before activation. A renewed
  credential is *not* a globally revoked principal; to re-register after
  terminal revocation, an operator must choose a new principal name.
- A coordination-enabled broker checks the authority at guest-entry and again
  immediately before every provider effect. An identity bridge checks it
  before forwarding every certificate-bound request. An unavailable authority,
  missing membership, invalid TLS path or reverted/stale registration fails
  closed. There is deliberately no cached positive admission or offline lease.
- A revocation committing **after** a provider request's final check cannot
  retract that already in-flight request. No globally instantaneous cancellation
  of previously dispatched effects is claimed.

### Provisioning workflow

All coordinator commands are host-only (`python -I -m aivm_secrets identity`),
not guest commands. Provision a trusted server certificate whose SAN matches
the `host` clients use; provision a trusted client CA, one operator certificate
and individual member certificates on the appropriate hosts. Fingerprints are
SHA-256 over the DER-encoded client certificate. The operator manually pins
member fingerprints; the coordinator does not enroll clients itself.

A coordinator database can be created independently of TLS enrollment:

```bash
python -I -m aivm_secrets identity coord-init \
  --directory ~/.config/aivm/secrets/coordination
```

The server command `identity coord-serve` then requires `--directory`, `--host`,
`--port`, `--server-certificate`, `--server-key`, `--client-ca` and one or more
`--operator-fingerprint` arguments. Do not invent a server certificate path
or a member fingerprint. Use actual material from the host's CA; the test
`python -m pytest -q tests/test_secrets_coordination.py` supplies a fully
working synthetic setup. A loopback bind is appropriate for a same-host smoke
test, not a remote-host deployment. On a LAN, configure a dedicated interface,
restrict inbound peers with the host firewall, and keep the service
unreachable by untrusted guest networks. A CA-valid server name is mandatory.

The trusted client config is a **0600 owner-only file** with schema:

```json
{
  "schema": 1,
  "host": "localhost",
  "port": 8743,
  "ca_file": "/etc/aivm-secrets/coord/ca.pem",
  "certificate_file": "/etc/aivm-secrets/coord/client.pem",
  "key_file": "/etc/aivm-secrets/coord/client.key",
  "principal": "agent-gh-repo-01"
}
```

Those paths are illustrative; provision the corresponding real files under a
trusted host-owned directory, with the TLS private key at mode 0600. `host`
MUST match the TLS server certificate. Operator config uses an operator
certificate; broker and bridge configs use registered member certificates
but the same `principal` string. Distinct logical grant groups should not
share the principal name merely because they use the same provider.

After starting the coordinator, register every member certificate under the
principal using an operator config:

```text
identity coord-activate --config operator-coordination.json
    --member-fingerprint CERT_DER_SHA256_HOST_A
    --member-fingerprint CERT_DER_SHA256_HOST_B
```

Host launch arguments (paths omitted here because these commands require the
operator's actual local policy and socket):

```text
serve --coordination-config broker-coordination.json
identity bridge --coordination-config bridge-coordination.json
identity coord-revoke --config operator-coordination.json
identity coord-status --config operator-coordination.json
identity revoke --coordination-config operator-coordination.json ...
identity oauth-revoke --coordination-config operator-coordination.json ...
```

**Both** the broker and bridge must be enabled for a complete bound-session
path. An omitted config gives the historical local-only behavior, not a
fallback. All hosts serving one globally revoked principal must register and
check with the *same* coordinator; a deliberately misconfigured older host is
outside the claim. The AIVM launcher does not yet automatically distribute
or enforce the coordination configuration across all participating hosts.

## 2. In-place credential renewal (two separate lifetimes)

**Access-token rollover:** a session created with `serve --oauth-vault` seals
an opaque session marker into `aivs1`, not the initial OAuth bearer token. On
every request `OAuthVault.current_lease(...)` resolves the latest access token
under the vault lock and keeps the lock until preflight and final dispatch
finish. The operator runs the existing `identity oauth-refresh` against the
same vault; subsequent requests use the updated token **without restarting
the broker or changing the guest's capability**. Refresh keeps the enrolled
epoch. Local OAuth revoke or re-enrollment changes epoch and permanently
invalidates the existing session. The vault does not silently refresh or retry
a provider exchange within a guest request; refresh-state uncertainty still
fails closed.

**Bound identity rollover:** `identity renew-bound` performs CAS renewal of the
existing guest certificate (same enrolled public key, new epoch) followed by
issuance of a new certificate-bound JWT for the *existing* broker capability.
The running mTLS bridge consults the enrollment registry for each peer, so
new certificate/JWT works without restarting broker or bridge; old certificate
or JWT is rejected. The operator must install the new public certificate and
JWT into the guest client. The guest private key stays private. This command
requires `--root`, `--subject`, `--csr`,
`--approve-key-fingerprint`, `--expected-epoch`,
`--expected-certificate-sha256`, `--capability-file`, `--jwt-output`; an optional
`--lifetime` bounds the JWT. It creates a new JWT file and never overwrites.
If renewal commits but issuance fails, **the old pair remains revoked**;
finish with `identity issue` for the new enrollment after addressing the
problem. A single atomic guest-side multi-file swap is not yet implemented.

**These are different from the global terminal coordinator revocation.**
Routine token/certificate renewal is allowed for an active registered
principal; global revocation is for irrevocable termination of that principal.

## 3. Durable idempotency for writes

With `--coordination-config` set, every *declared write* requires a top-level
`idempotency_key` (ASCII `[A-Za-z0-9_-]`, 8–128 characters). The key is not a
policy argument and never influences the path, body, authorization, or route.
The broker derives a SHA-256 key scoped to the **global principal**; unlike a
session grant ID, it persists across broker restarts and changes of member
host. A separate SHA-256 fingerprint binds the request and exact policy to
that key. The coordinator atomically records the reservation **before**
the first credentialed provider write. Reserving a used key, even with an
identical request after a known successful response, is denied as
`outcome_unknown`; changing the request under that key is likewise denied.
There is no replay or success-result cache. A failed, abandoned, or ambiguous
reserved key is never automatically retried; reconcile with the provider
before choosing a distinct key.

The guest may use `aivm-secrets-guest invoke issue.comment --arguments ...
--idempotency-key stable-issue-comment-001` (the exact operation must exist in
the selected manifest). Existing alias commands do **not** yet have a
provider-independent idempotency-key flag; use `invoke` for keyed writes.

For a provider that supports `Idempotency-Key`, an operation may include
`"idempotency_header":"Idempotency-Key"` in the manifest. Only declared
writes accept this, and only after a durable reservation does the host insert
the **derived** hexadecimal key in the outbound request. Provider schemas and
header semantics vary; acceptance of a header does not itself prove provider
idempotency. Providers without header support still get the local/global
**at-most-one dispatched attempt per coordinator key**, not provider-side
transactional idempotency.

Without a coordinator, legacy unkeyed writes retain their old semantics.
A manifest declaring a provider idempotency header requires coordination and
a key; otherwise dispatch is denied. All variants preserve local policy
approval, request budgets, audits, authorized-effect construction, response
projection and write-error uncertainty handling.

### Operational limits that affect the guarantee

- Coordinator DB backups must be protected from rollback; this version lacks
  an external monotonic witness or replication quorum. A restored old DB
  could forget a revocation or reservation.
- The coordinator is a single availability/failure domain. Its outage blocks
  requests, which is deliberate, not graceful availability.
- A `completed` reservation attests the broker saw a provider success; it does
  not necessarily mean the guest received the reply. A retry must not issue
  another effect even if guest delivery failed.
- Cross-host request budgets remain separate from the idempotency ledger;
  granting independent sessions on different hosts can increase aggregate
  requests. Operators must choose narrow limits for each host.
- No automatic cross-host OAuth vault replication or secure token transport
  is implemented. Only the coordination decision is shared. Renewal of the
  coordinator's own TLS certificates currently requires restarting the
  coordinator/client processes (not the bound guest session).
- Renewing an OAuth bearer does not extend the broker session's configured
  lifetime. Certificate/JWT renewal requires the operator to securely install
  the new material into the guest; no atomic guest file-swap is supplied.
- The central ledger never executes provider requests and does not store
  provider credentials or raw request bodies. Denial codes do not reveal
  whether a key was previously reserved for the same or different payload.

## Tests and proof boundaries

`tests/test_secrets_coordination.py` covers durable local SQLite decisions,
atomic concurrent reservation, real mutual TLS with distinct member host
certificates, persistent tombstones, offline denial and the real bound bridge
under cross-host revocation. `tests/test_secrets_core_extensions.py` covers
broker restart/replay refusal, request-key conflicts, ambiguous write outcome,
real HTTPS idempotency-header emission, concurrent OAuth token update through
a live broker, and certificate/JWT rollover through a running mTLS bridge.
`tests/test_secrets_core_api_contract.py` keeps module classification and
symbol references synchronized.

These are **synthetic same-machine integration tests**, not evidence of
cross-datacenter availability, hardware root of trust, anti-rollback,
production provider compatibility, Rust parity or complete Python formal
verification. See [core parity policy](garrett-python-core-parity.md).
