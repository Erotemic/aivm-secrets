# Native coordinator operator control

`garrett-coordinatorctl` activates a principal, records terminal revocation, or
reads status through the existing schema-1 mTLS coordinator protocol. It runs
against either Python or native Rust authorities. It needs neither Python nor
SQLite at runtime; building the optional native server remains a separate step.

```sh
cargo +nightly-2026-09-17 build --manifest-path rust/Cargo.toml -p aivm-secrets-garrett --no-default-features --bin garrett-coordinatorctl
```

The operator supplies a private config in an owner-private host directory.
The format is the same as a broker member's coordinator config, with the
**operator's own** certificate and private key selected instead:

```json
{"schema":1,"host":"localhost","port":9443,"ca_file":"/private/coordinator/ca.pem","certificate_file":"/private/operator/client.pem","key_file":"/private/operator/client.key","principal":"shared-agent-principal"}
```

Paths and port represent operator-provisioned material. The server must pin the
operator's full-certificate DER SHA-256 in its operator list. A member identity
does not gain operator authority by using this program or config format; the
server authenticates and checks roles for every request. Operator authority
also does not imply membership in the selected principal. The broker/guest
protocol cannot select this operator client or its private configuration.

```sh
rust/target/debug/garrett-coordinatorctl --config /private/operator/client.json status
openssl x509 -in /private/member/client.pem -outform DER | sha256sum
rust/target/debug/garrett-coordinatorctl --config /private/operator/client.json activate --member MEMBER_CERTIFICATE_DER_SHA256
rust/target/debug/garrett-coordinatorctl --config /private/operator/client.json revoke
```

Replace `MEMBER_CERTIFICATE_DER_SHA256` with the 64-character lowercase hash.
Activation accepts repeated `--member` flags for distinct members, up to the
existing protocol limit of 32. The principal comes from the private config.
Existing names, including revoked names, cannot be activated again. Recovery
requires an explicitly chosen new principal.

## Receipts and uncertainty

The CLI prints one version-1 JSON object and exits zero only on a complete typed
receipt. Failure exits one with a fixed error code; arbitrary remote error text
and extra reply fields are refused. Successful activation requires `active:true`
and revision 1. Successful revocation requires `active:false` and a positive
integer revision. Status may report `active:false, revision:null` for a missing
principal. **Absence is not a terminal revocation:** a missing name may still be
activated later, while a committed tombstone cannot.

Both Python and native operator clients now distinguish failure before request
submission (`unreachable`) from an uncertain mutation after possible submission
(`outcome_unknown`). A malformed mutation receipt is also uncertain. Status has
no mutation to reconcile and reports malformed replies as `upstream_response`.
Definite fixed server denials remain denials. Neither client caches positive
authority, retries a request automatically, or falls back to another transport.

After uncertainty, inspect status and reconcile the intended action with the
operator's records. Status is not a transaction identifier or proof of which
operator submitted an activation/member list. Do not treat it as permission to
repeat a possibly committed action. Broker-member calls keep their existing
fail-closed `revoked` transport behavior, now with complete typed Python
acknowledgement validation matching the native member contract.

## Evidence and limits

The deterministic fault fixture runs the real Python mTLS handler through
authorization and SQLite commit, then drops the reply. The previous Python
client misclassified both committed activation and committed revocation as
`revoked`; both current clients preserve uncertainty and make one attempt.
Other process tests cover both authority backends, role separation, preemptive
tombstones, native restart, untrusted CAs, and revocation of running native
account/manifest brokers. The shared frozen reply corpus checks JSON types,
missing state, wrong flags/revisions, extra fields and sanitized denials.

`GarrettCoordinatorReply.lean` checks the actual extracted native receipt gate:
exact admission, active/missing-state refusal for revocation, valid absent status,
exact activation receipt, and composition with successful extracted revocation.
`COORD-OPERATOR-RUST-01` records the remaining parsing, transport-phase, TLS and
trusted remote-state premises. The proof does not establish remote SQL commit,
durability, rollback protection, whole-service mediation or confidentiality.
No live account, physical TPM, VM or cross-machine deployment is tested here.
