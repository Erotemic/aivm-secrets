# Optional exact-write approval for the native broker

The experimental `manifest-https-v1` backend can require a host operator to
approve one exact write. This is optional: `writes: "allow"` permits authorized
writes without per-request approval, and `writes: "deny"` refuses them. All
three modes retain `request_limit: "unbounded"`. No TPM is required for local
approval; a separately selected TPM profile changes identity-key custody.

In the bridge's existing private configuration, select:

```json
{
  "provider": {
    "profile": "manifest-https-v1",
    "writes": "approve",
    "request_limit": "unbounded",
    "control_socket": "/run/user/1000/aivm-secrets/CHANNEL/control.sock"
  }
}
```

This fragment supplements the existing provider, policy, disclosure and
identity fields described in [the native workflow](standalone-rust-github-workflow.md).
Replace `CHANNEL` with the actual 32-hex binding channel and use a short absolute
path (at most 100 bytes). Its directory must already exist, belong to the
broker's effective UID and have no group/other permissions. The configured
binding owner must be that UID. Startup refuses an occupied path, unsafe
ancestors, a different basename or the same path as the guest listener.
`control_socket` is rejected in allow/deny modes.

**Keep `control.sock` on the trusted host.** Forward only the separately
configured guest listener into a VM. The control listener checks the actual
kernel peer UID and uses mode 0600, but an SSH forward could connect as the
trusted host user. Peer credentials do not establish that a forwarded caller
is the human operator.

A write without approval returns `approval_required` and an exact-request
digest without making a provider call, including credentialed preflight. The
host can review pending normalized arguments and approve that digest:

```bash
aivm-secrets sessions
aivm-secrets pending CHANNEL
aivm-secrets approve DIGEST --session CHANNEL
aivm-secrets deny DIGEST --session CHANNEL
aivm-secrets revoke CHANNEL
```

These existing Python operator commands discover the native listener when its
directory is `$XDG_RUNTIME_DIR/aivm-secrets/CHANNEL`. They speak the version-1
process protocol; they do not import the Rust implementation. Approval displays
the request and asks for confirmation; `--yes` selects unattended approval.
`--ttl` accepts 1–900 seconds, default 300. Digest prefixes need at least eight
characters and must match exactly one pending request. This interoperability
does not make native audit files compatible with Python's audit-chain tools;
avoid pruning a directory while its guest listener remains in use.

The guest explicitly resubmits the same request after approval. Approval binds
the normalized policy digest, actual root grant ID and normalized operation and
arguments. A different request or broker session does not share authority.
Retry metadata is excluded from the request digest, and coordinated writes
still need their independent durable retry reservation. Semantic writes need
approval even when their declared HTTP method is GET. Ordinary reads preserve
approval slots. Pending requests and live approval slots each have a fixed
16-entry implementation bound; this is memory containment, not a request quota.

Approval is consumed before preflight and remains spent after preflight,
provider, audit or disclosure failure. Its TTL is an admission window, not a
cancellation mechanism for an already admitted action. Host revocation withdraws
root authority before waiting for audit, independently of the provider mutex;
late dispatch and reply release recheck it. A provider write already sent may
have happened, so a fenced or failed reply remains `outcome_unknown`. A new
approval never reverses root revocation. Host status reports local root authority;
it does not replace the guest request’s fresh global-coordinator check.

## Evidence and limits

[`approval.rs`](../rust/crates/aivm-secrets-garrett-core/src/approval.rs) is the
actual Rust issuance/consumption code translated by Aeneas.
[`GarrettApproval.lean`](../proofs/GarrettApproval.lean) checks the exact issuance
deadline and that approved writes are admitted exactly when a matching,
unexpired slot exists, consume it, and cannot reuse the consumed slot. Separate
contracts cover reads, allow and deny modes. There is no added security axiom.

[`test_rust_approval.py`](../tests/test_rust_approval.py) re-evaluates a frozen
90-row corpus against Python's actual `machine.admit`, compares it with the
native gate, and exercises real native Unix/TLS/provider processes. Cases cover
digest parity, expiry, failed writes/preflight, concurrent reuse, guest denial,
unsafe endpoints, operator CLI interoperability and revocation during blocked
provider I/O. All credentials and providers in these tests are synthetic.

The proof does not establish socket isolation, SHA-256 or JSON correctness,
clock behavior, slot-store linearization, filesystem/audit durability or
complete native I/O mediation. Those remain explicit reviewed/tested adapter
premises under `APPROVAL-RUST-01`. The approve configuration and its public
`approval_required` digest are **not represented in the existing W4/W5
whole-trace model**. Delegation, request budgets, broad Python/Rust parity,
independent security review and live deployment remain open. This feature does
not establish whole-service confidentiality or production readiness.
