# Renew a native client identity without restarting its broker

The native authority now has a host-only `rebind` operation. After the existing
same-key certificate renewal, it wraps the original opaque broker capability
in a JWT bound to the current certificate and enrollment epoch. The account
and manifest broker processes keep running. Their provider credential and
original grant stay inside the existing session.

The operator keeps the original host-issued JWT in an owner-only source file,
uses the existing `renew` action with its CSR approval and expected old
certificate/epoch, then calls:

```bash
garrett-authority rebind --root /private/authority --request /private/rebind.json
```

The private request file has this shape; use actual coordinates returned by
renewal rather than the illustrative epoch and thumbprint:

```json
{
  "subject": "vm-test",
  "surrogate_file": "/private/original.jwt",
  "expected_epoch": 1,
  "expected_thumbprint": "<current certificate SHA-256 in base64url>",
  "output": "/private/rebound.jwt",
  "client_assurance": "any-enrolled",
  "lifetime": 300
}
```

The output is a new 0600 host file and is never overwritten. The response gives
its path, target/source epoch, certificate thumbprint and expiry, without the
JWT or opened capability. Install the new public certificate and JWT into the
guest through the existing operator delivery workflow. The private key stays
in place. Mixed old/new pairs fail closed while installation is incomplete;
a single atomic multi-file guest swap remains future work.

This is a two-stage operation: certificate renewal and JWT publication are not
one transaction. If publication fails, the old enrollment remains revoked.
Review `public-client` for the current coordinates and retry `rebind` with the
retained original JWT and a new, unused output path. The source certificate
must still be retained, its key must match the current enrollment, and its
issuer signing key must remain enabled. CA rotation, key rotation and pruned
source material do not silently select another identity or trust root.

`client_assurance` selects `any-enrolled` or `attested-tpm`. Existing issuance
checks enforce the selection; software enrollment cannot satisfy the latter.
Renewing an attested identity still needs the existing fresh attestation
workflow. No TPM or VM is needed for the tested software-key workflow.

## Authorization and lifetime boundaries

Rebinding is an explicit privileged host authorization, not a guest endpoint.
An expired source JWT can identify the same previously issued opaque capability
for its trusted operator. It is not accepted as proof of a live guest session.
The current target must be active, unexpired, the expected certificate/epoch,
and the same issuer, audience, subject and public key as the verified source.
A source from a later epoch is refused. An owner-only source file does not
replace signature/AEAD verification or certificate validation.

The original broker capability is unchanged. Rebinding cannot extend its
lifetime, change its operations, reactivate a revoked local target or remove
a terminal global coordinator tombstone. A fresh identity JWT may outlive the
underlying grant; the broker still refuses an expired grant. An explicit fresh
provider session is a separate authorization decision.

## Implementation-linked proof scope

`rebinding::permitted` and `rebinding::rebind` are extracted from the Rust
functions used by the host operator path. Twelve `GarrettRebinding.lean` lemmas
check exact acceptance, identity/key continuity, target CAS, inactive/expired
refusal, refusal before opening or issuing, opening failure and successful
carry-forward of the same opaque capability to the issuer. The existing
issuer composition still checks active enrollment, selected assurance,
bounded issuance and acknowledged publication.

The concrete adapter holds a shared authority lease from source verification
through current-target comparison, opening and no-replace publication. Normal
issuance time is sampled after the authority wait and certificate preparation;
explicit operator time is a trusted administrative/test input.
Participating enrollment/key writers take the exclusive lease. The verified
source certificate supplies its own public-key fingerprint to the guard; using
the target fingerprint instead would defeat continuity. A W3 negative edit
checks that substitution, along with removal of the lease or target CAS.

`REBIND-RUST-01` records authorized host callers, ownership/no-symlink file
adapters, signature/AEAD and certificate/fingerprint correctness, trusted clocks,
lease participation and publication durability. The Lean results do not prove
those adapters, host/guest isolation, remote installation or whole-service
confidentiality. W4/W5 retain their separate, narrower modeled trace scope.

## Executed runtime scenarios

`tests/test_rust_bound_renewal.py` starts actual native authority/client/bridge
processes and a recording synthetic HTTPS provider. Both native profiles keep
their process ID across same-key renewal and accept only the new certificate /
JWT pair. An independent Python verifier confirms byte-for-byte preservation
of the opaque inner capability. The old pair and both mixed pairs are refused
without provider HTTP.

Adversarial cases cover stale epoch/certificate, a different key or subject,
local revocation, retired signing key, tampered JWT, private-input failures,
no-overwrite output, software-versus-TPM selection, a concurrent authority wait,
pruned source material, expired source/inner lifetimes and terminal global
revocation. The latter remains enforced even after new local identity material
has been issued. Providers and credentials are synthetic.

```bash
python dev/verification/system.py --proofs --full-tests
python dev/verification/garrett.py record
python dev/verification/garrett.py mutate --mutation-filter '^rebind '
```

The filtered command checks the new rebinding mutations; it is not the full
campaign. CORE-03 remains a tested native subset with explicit adapter and
cross-language coverage limits, not an all-input equivalence claim.

See [atomic guest identity bundles](guest-identity-bundles.md) for explicit local
certificate/JWT activation with Python and Rust clients after same-key renewal.
Host renewal and guest activation remain separate operations.
