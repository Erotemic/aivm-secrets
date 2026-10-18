# Native named operations

The standalone native client can invoke a host-defined operation without
constructing a protocol frame by hand. It uses the existing mTLS connection,
software or explicitly selected TPM key, and host-issued capability. It adds
no authority and requires no AIVM installation.

With a private client config selecting an installed identity bundle:

```bash
rust/target/debug/garrett-client --config /private/guest/client.json invoke ticket.view --arguments '{"ticket":7}'
rust/target/debug/garrett-client --config /private/guest/client.json invoke ticket.edit --arguments-file request.json --idempotency-key logical-operation-001
```

These operation names match the synthetic ticket fixture. Real names and
arguments must come from the selected host policy. A legacy config selecting
`certificate` instead of `identity_bundle` also requires
`--capability-file /private/guest/capability.jwt` immediately before `invoke`.
Combining a bundle with a separate capability file is refused. Each call loads
one configured certificate/JWT snapshot; there is no identity fallback.

Arguments default to `{}`. Supply one JSON object with either `--arguments`
or `--arguments-file`; `--arguments-file -` reads stdin through EOF. Input is
bounded to 16,384 bytes, duplicate object keys are refused, and options form a
closed set. Argument files contain untrusted request data and may be ordinary
readable files or explicit symlinks. FIFOs, devices and directories are refused.
Keep credentials in the existing private config/capability/bundle files; a
provider credential is never a client argument.

The client prints the full public broker reply as one JSON line. It exits zero
only for a version-1 reply with `ok: true`; broker denials and uncertain outcomes
retain their structured error and exit one. Local/transport failures print a
fixed error code to stderr and exit one. An invalid version/`ok` wrapper after
sending is `outcome_unknown`. There is no automatic retry. The older raw stdin
interface retains its existing exit convention: receipt of a broker denial
still exits zero, so scripts using that interface must inspect `ok`.

Writes still require host permission. Coordinated writes require a retry name;
reads and uncoordinated sessions reject it. Retry names contain 8–128 ASCII
letters, digits, hyphens or underscores. The broker derives the principal-scoped
reservation key and sends it upstream only when the operation declares the
reviewed idempotency header. A spent name never authorizes replay, including
after `outcome_unknown`. Reconcile the provider outcome before deciding whether
another intended action needs a new name. The client never selects an arbitrary
URL, credential or header.

## Evidence and scope

`tests/test_rust_invoke.py` exercises real native clients, brokers and a synthetic
HTTPS provider with both bundle and legacy inputs. It compares request/effect
semantics with the Python reference, exercises both coordinator implementations,
and checks forbidden writes, replay, provider failure, revocation and malformed
post-send replies. Its separate 2,391-row byte corpus compares retry syntax with
an independent Python predicate; that fixture requires the explicit conformance
build. The process workflows also run without conformance support.

`GarrettRetryKey.lean` checks the actual extracted Rust `retry_byte` and
`valid_retry_key` functions shared by client and host. Its exact contract accepts
all and only the bounded ASCII grammar and excludes CR/LF anywhere in an accepted
name. The existing dispatch and coordinator-history proofs remain separate.
This does not prove the CLI, JSON conversion, hashing, SQL durability, native I/O
mediation, exactly-once provider effects, broad Python/Rust parity or whole-service
confidentiality. No live provider or TPM is required for these synthetic tests.
