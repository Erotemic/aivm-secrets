# Native coordinator admission and keyed writes

Native account and manifest sessions can now select `coordination_file` in their
private provider configuration, inside the bridge's `provider` object.
It is a host selection, not a guest-frame field. The referenced file uses the existing Python coordinator
schema, for example:

```json
{
  "schema": 1,
  "host": "localhost",
  "port": 9443,
  "ca_file": "/private/coordinator/ca.crt",
  "certificate_file": "/private/coordinator/member.crt",
  "key_file": "/private/coordinator/member.key",
  "principal": "shared-agent-principal"
}
```

These paths name actual operator-provisioned material, not files created by this
example. The member identity belongs to the trusted host broker and is distinct
from the guest identity. Its private key stays on the host. Provision the
existing Python server and manually pin member/operator fingerprints using
[the coordinator workflow](garrett-python-core-extensions.md). The native client
implements check/reserve/finish. The optional [native server](native-coordinator-authority.md)
and separate [operator client](native-coordinator-control.md) now supply the
existing activation/revocation/status protocol without adding guest operator verbs. Neither component requires TPM hardware.

The selected CA and hostname are mandatory. Connections use mTLS/TLS 1.3,
a bounded fixed endpoint and closed metadata vocabulary, with no proxy,
redirect, positive admission cache or automatic request retry. The explicit
`localhost` exception now works in file-loaded Python configurations too;
other names retain the existing strict hostname grammar.

## Behavior

Every coordinated provider request and control operation checks current global
membership. Provider emission checks again after TLS setup; a revocation during
setup stops credentialed HTTP. An unavailable authority fails closed. A check
is an admission point, not cancellation of an action already in flight.
Control paths sample their clocks and recheck the held OAuth token after the
coordinator wait. The new positive-acknowledgement delay regression reproduced
expired account `describe` and `renounce` acceptance before that ordering fix;
eight outer/current-token cases now cover both backends and control verbs.

All coordinated manifest writes require a guest retry name in the request:

```json
{
  "operation": "ticket.edit",
  "arguments": {"ticket": 7, "text": "hello"},
  "idempotency_key": "logical-operation-001"
}
```

The retry name is stripped before policy/argument compilation and cannot select
a destination or expand authority. It is rejected on reads and on sessions
without coordination. Before calling the provider interpreter, the broker
obtains a durable reservation scoped to the configured global principal and
retry name. Existing reservations, including completed or uncertain writes,
are never replayed. A changed body cannot reuse the name. Use a new name only
for a new intended action; reconcile uncertain effects with the provider.

The [native `invoke` command](native-operation-client.md) constructs this same
request without a hand-written frame. Client and host share the extracted
8–128-byte ASCII retry-name validator, checked in `GarrettRetryKey.lean`; this
syntax proof is separate from reservation durability and dispatch ordering.

Operations may explicitly declare `"idempotency_header": "Idempotency-Key"`.
Only then does the native broker send the derived 64-character reservation key
to the approved provider. It does not send a guest-selected header. An explicit
header requires the keyed coordination path; no unkeyed fallback is accepted.
A conflicting static header is refused. Preflight stays read-only and does not
consume a write reservation. All provider bytes still pass the single W6 encoder
before socket creation; the optional derived header adds one slot beyond the
eight host-policy headers.

A provider error or a failure recording completion after emission cannot return
success. The reservation remains spent. Global revocation after emission can
therefore produce `outcome_unknown`; it does not undo the action.

## Checked scope

`coordination::dispatch` is the actual extracted Rust continuation used by native
manifest dispatch. Seven `GarrettCoordination.lean` lemmas check denial before
provider invocation, reservation refusal, provider error propagation, uncertain
completion, successful read/write witnesses and the conditional acknowledged
write contract. A dedicated core denial preserves the fixed `revoked` code
through account execution; the existing authorization and disclosure proofs
handle its impossible local-guard cases without weakening their statements.

The proof does not establish that a remote positive response is honest or
durable. `COORD-RUST-01` names the authenticated trusted server, one local SQLite
writer, no rollback/split writer, participating members and native callback/I/O
correspondence premises. This is not distributed consensus, an anti-rollback
ledger, exactly-once provider execution or whole-service information-flow proof.
W4/W5 compile separately; their modeled guest traces do not include the new
coordinator observer. W0/W3/W6 explicitly inventory that additional network sink.

`tests/test_rust_coordination.py` exercises real native processes, mTLS and local
recording HTTPS providers. Tests cover terminal revocation, control denials,
revocation during provider TLS, outage after a positive call, unregistered or
wrong members, wrong trust anchor, strict retry syntax, concurrent hosts,
restart persistence and uncertain completion. Both live Python and native Rust
brokers take turns dispatching successfully, then refuse the other's retry
name against the same server. The derived provider key interoperates in both
directions. Sixteen policy-field cases also compare native parsing/compilation
with the independent Python reference. Rust units check typed acknowledgements,
HTTP framing and callback ordering/no retry.

CORE-07/08/09 remain **partial**, rather than missing or parity-complete. The
[optional native authority](native-coordinator-authority.md) now serves the same
protocol/schema alongside the independent Python server. Both are exercised by
the native/Python broker workflows, frozen reply/state vectors and restart cases.
Its core membership and terminal decision/history proofs do not refine SQL/TLS
or whole-service I/O. The [policy identity follow-up](verified-policy-normalization.md)
now rebuilds normalized policy before fingerprinting and compares it with Python,
including actual durable coordinator records. Duplicate keys remain refused
regardless of fingerprint; all-input normalization equivalence is unproved. Legacy socket
forwarding, broader core equivalence and deployment
on genuinely separate hosts remain unvalidated.

```bash
python dev/verification/system.py --proofs --full-tests
python dev/verification/garrett.py record
python dev/verification/garrett.py mutate --mutation-filter '^coordinated '
```

The filtered command checks only the new controller mutations. A full campaign
requires omitting the filter. All tests use synthetic credentials. No live
provider account, VM, TPM or existing coordinator is modified by the gate.
