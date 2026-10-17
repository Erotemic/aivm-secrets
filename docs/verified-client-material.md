# Native client key and CSR bootstrap

The optional Rust client can create an **exportable software P-256 key** and a
signed possession request. This neither enrolls the key nor supplies TPM/VM
attestation. Trusted host approval still binds the exact public-key fingerprint.
The work is experimental and unaudited.

Create an identity in existing principal-owned private directories:

```bash
garrett-client request --key-mode software \
  --key /private/client.key --csr /private/client.csr
garrett-client inspect-csr --csr /private/client.csr
```

Success prints the key fingerprint, the two paths and the explicit software-key
assurance description. It never prints private-key material. The CSR and key
match Python's P-256/SPKI SHA-256 contract; the CSR has the fixed untrusted-request
name and requests no certificate extensions. The authority continues to choose
certificate subject, lifetime and assurance. Explicit software mode is required;
a TPM selection cannot fall back to software generation. TPM mode uses an already-provisioned pinned key and requires the separate
configuration described below. It creates no software private-key file.

## Request from a provisioned TPM key

```bash
garrett-client request --key-mode tpm2 \
  --tpm-config /private/tpm-request.json --csr /private/client.csr
```

The private version-1 JSON configuration contains exactly `schema: 1`, `tcti`,
`persistent_handle`, `authorization_file`, `public_area_file` and `work_directory`.
These use the same fixed-tool, pinned-public-area and private-authorization
contracts as the TPM TLS signer. No client certificate is needed to create the
CSR. Each signature is verified against the pinned public key before its request
can be published. An existing CSR target, wrong authorization, changed public
area or an extra software-key configuration field fails closed. TPM errors never
select a software generator.

The result contains only the CSR path, public fingerprint and an explicit notice
that provenance must be independently enrolled. Local attributes and a valid
signature alone do not create an attested identity. Trusted host `enroll-tpm`
still consumes fresh creation evidence under an independently provisioned AK
pin and binds that exact SPKI. The tests exercise that complete native sequence
and a provider call with isolated software TPMs; they establish no physical
silicon, EK provenance, PCR policy, signing-oracle isolation or anti-clone claim.
The operator provisions TPM key material separately; this command does not
create, replace or evict a persistent TPM key.

## Publication and recovery

Both paths must be absolute UTF-8 paths under controlled private directories.
The client opens and holds directory descriptors without following symlinks,
checks kernel ownership/mode and refuses existing targets of any type. Aliases
for the same target are rejected before key generation. Publication stages and
syncs each file, then uses a no-replace rename and directory sync. The private
key is published before the CSR. Key/CSR files have private modes; the client
also checks that returned parent coordinates still name the held inodes.

Two separate filenames cannot be atomically published together. If publication
of the key is uncertain, or any CSR step fails after key acknowledgement, the
command reports `outcome_unknown`. Retain and inspect the key; do not overwrite
it or create another identity under that name. To recover only the public request:

```bash
garrett-client csr-from-key --key-mode software \
  --key /private/client.key --csr /private/recovered.csr
```

Recovery reads a private regular P-256 key through a held descriptor and creates
a new CSR without replacing either file. Its public fingerprint can be compared
with a prior request or host approval. Private staging files may remain after
failed writes/publication; they are not automatically adopted or deleted.
Existing target refusal happens before generation, while races during final
publication conservatively report uncertainty. Nonparticipating same-UID writers,
root administrators and filesystem rollback are outside this boundary.

## Conditional source proof and evidence

[client_material.rs](../rust/crates/aivm-secrets-garrett-core/src/client_material.rs)
is the actual extracted controller used by the native file adapter.
[GarrettClientMaterial.lean](../proofs/GarrettClientMaterial.lean) checks:

- A failed private-key step prevents the CSR step; its result is independent of
  what the CSR adapter would otherwise do.
- An uncertain key result remains uncertain.
- A failure after key acknowledgement cannot be reported as unchanged or success.
- Success requires both storage acknowledgements, under their explicit durability
  contracts, and the successful path is realizable.

These theorems prove controller order and result classification. They do not
prove entropy, P-256/signature/SHA-256 implementations, PEM/ASN.1 parsing,
filesystem durability, descriptor checks or the complete CLI/I/O history.
The native adapter's crypto/key checks and publication operations are tested
boundaries, not hidden proof premises established by the controller.

[Interoperability and fault tests](../tests/test_rust_garrett_client_material.py)
use Python as an independent CSR/private-key oracle, accept a Python-generated
key for Rust recovery, and execute Rust-generated material through native
authority enrollment, TLS and provider dispatch. They exercise existing files,
symlinks, FIFOs, hardlinks, ambiguous software-mode requests, unsafe recovery keys,
concurrent publication and actual kernel file-size write failures. The CSR-write
failure test retains the same private key and successfully recovers its request.
