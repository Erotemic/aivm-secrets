# Atomic guest certificate/JWT bundles

The standalone Python and native Rust clients can now consume a certificate and
outer JWT from one private, versioned file. An explicit installer publishes that
pair atomically under an expected-current digest. The existing private key,
server CA, socket and broker wire format stay separately configured. This is a
same-key activation step after host renewal/rebinding; it grants no CA authority.

## Install and replace

Use an existing owner-private directory (mode 0700) and owner-private input files
(mode 0600). Paths must be absolute. Parent components of the destination and
bundle readers cannot be symlinks. Use the installer rather than writing a
bundle by hand: it also establishes the private `.bundle.lock` used by readers
and writers in that directory. Output names `.bundle.lock` and names starting
with `.bundle-` are reserved, so a staging file can never be the active target.

```sh
aivm-secrets identity install-bundle \
  --certificate /absolute/guest/new-client.pem \
  --jwt-file /absolute/guest/new-outer.jwt \
  --output /absolute/guest/identity.json
```

The result contains `path`, the lowercase hex SHA-256 `digest` of the exact file
bytes, and the public certificate's base64url `certificate_sha256` thumbprint.
It never prints the JWT. Retain the digest for the next explicit replacement:

```sh
aivm-secrets identity install-bundle \
  --certificate /absolute/guest/renewed-client.pem \
  --jwt-file /absolute/guest/renewed-outer.jwt \
  --output /absolute/guest/identity.json \
  --expected-current PREVIOUS_64_CHARACTER_HEX_DIGEST
```

`garrett-client install-bundle` accepts the same flags. Initial installation
refuses an existing target; replacement requires the current digest and a valid
existing bundle. A stale digest is `denied`. An unsafe file is refused before
replacement. Malformed or mismatched pairs are `invalid_capability`. Duplicate
JSON fields, extra fields, unknown versions and certificate chains are refused.

## Consume one snapshot

Python CLI:

```sh
aivm-secrets identity call --socket /absolute/guest/identity.sock \
  --ca /absolute/guest/server-ca.pem --key /absolute/guest/client.key \
  --identity-bundle /absolute/guest/identity.json \
  --request '{"operation":"profile.read","arguments":{}}'
```

The Python `identity.client.bound_call` API also accepts `identity_bundle` in
place of `certificate` and `jwt_file`. Its TLS loader reads the public
certificate from an anonymous Linux temporary-file descriptor exposed through
`/proc/self/fd`; `tempfile.TemporaryFile` does not require Python to expose
`os.memfd_create`. No JWT or private key is staged. On a system lacking a
usable anonymous temporary file or `/proc`, bundle-based TLS loading fails
closed. The self-contained `aivm_secrets/guest.py` launcher still uses its
existing separate-file interface; this increment adds no AIVM adapter.

Native client configuration selects `identity_bundle` **instead of**
`certificate`. Keep the existing explicit `software` or `tpm2` key configuration.
There is no software fallback and no new TPM provenance claim.

```json
{"schema":1,"key_mode":"software","socket":"/absolute/guest/identity.sock","server_name":"localhost","server_ca":"/absolute/guest/server-ca.pem","private_key":"/absolute/guest/client.key","identity_bundle":"/absolute/guest/identity.json"}
```

With this configuration, raw stdin is the existing version-1 frame with
`capability` omitted; the native client inserts the snapshot's JWT before
transport. Supplying another capability is an error. The three supported native
`gh pr view/diff/checks` aliases use that same snapshot without
`--capability-file`. Existing separate-certificate/token configurations remain
usable. Broker-side authorization is identical for both interfaces.

## Failure and assurance scope

Schema 1 contains exactly `schema`, `certificate` (one certificate PEM) and `capability`
(the opaque outer JWT). It contains no private key, CA configuration, host path
or provider credential. Local parsing checks token profile/claim shapes and the
certificate thumbprint binding; it **does not authenticate the token**, validate
a CA chain or client EKU, or accept it as authorization or require it to be currently valid. Every broker call still
verifies signature, lifetime, enrollment epoch, TLS peer and grant conditions.

Installers hold an exclusive lock through reading/validating the current file,
comparing its digest, staging a private durable sibling, atomic rename and
parent-directory fsync. Readers hold a shared lock while taking one snapshot.
All writers must cooperate; same-owner/root replacement and snapshot rollback
are outside this guarantee. SHA-256 collision resistance and filesystem/locking
semantics are assumptions, not proved by the controller.

Before publication, a failure leaves the active file unchanged. A private
staging file may remain. Once publication starts, any failure is
`outcome_unknown`: the new file may be active. There is no automatic restoration
or retry. Inspect the current file digest (for example with `sha256sum`) and
resolve the uncertainty explicitly. No private-key rotation or crash-recovery
cleanup service is included.

Host enrollment renewal and guest installation are separate operations. The
old pair can be fenced before delivery; calls then fail closed until installation.
An in-flight call may retain an old complete snapshot and face current broker
authorization. This is not uninterrupted availability or a failure-atomic
transaction spanning host and guest. No live VM, hardware TPM or provider
compatibility result follows from the synthetic tests.

`proofs/GarrettBundle.lean` checks the actual extracted native CAS controller:
exact byte comparison, no staging/publication on a mismatch or current-read
failure, no publication after staging failure, conservative publication
uncertainty, and success requiring matching state and both acknowledgements.
It includes a successful-install witness. JSON, hashes, certificates, locks,
filesystem rename/fsync and client loading remain reviewed/tested adapters.
This does not prove whole-service secrecy or atomic filesystem semantics.

Use `lake env lean -DwarningAsError=true GarrettBundle.lean` from `proofs/`
for focused compilation, and the existing usable-system gate for the required
Python/native scenarios. Tests use synthetic credentials only.

## Verify the source actually exercised by isolated subprocesses

The full system gate runs some identity commands with `python -I` to avoid
importing code from the caller's current directory or PYTHONPATH. A regular
source-tree import can therefore be current while those commands import an
older installed version. `dev/verification/system.py` now checks the isolated
import location before the Rust build. When it detects an outdated install,
refresh the active environment with `uv pip install -e . --no-deps` from this
checkout, then rerun the gate. Do not change those tests to non-isolated
subprocesses as a workaround.
