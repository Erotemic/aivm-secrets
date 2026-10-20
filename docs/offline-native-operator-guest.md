# Standalone native Garrett: offline operator and guest

This is a **runnable operator-facing workflow**, not another model of Garrett.
It uses the actual native Rust authority, broker and guest client to do useful
GitHub-shaped work against a disposable local HTTPS provider. Python generates
synthetic CA/provider material and configures the example; it does not make
credential-access, TLS, authorization, revocation or disclosure decisions.

This demonstration makes no network request to GitHub, performs no OAuth login,
does not use real credentials, requires no AIVM checkout, and does not run the
heavy Charon, full pytest or Lean verification gates.

## Run it

From a trusted checkout with the Python package/test dependencies installed:

```bash
cd ~/code/aivm-secrets

# Only needed when the native executables have not been built.
cargo +nightly-2026-09-17 build --manifest-path rust/Cargo.toml --bins

# Single command: enroll, issue, read, deny, revoke, inspect provider effects.
python dev/offline_native_guest.py
```

To save the synthetic host and guest files and a redacted summary for inspection:

```bash
python dev/offline_native_guest.py \
  --workspace .tools/offline-garrett-run-01
```

The specified workspace must not exist. It is created with private permissions;
the script never overwrites a credential or identity file. To use existing
binaries in a different directory, pass `--bin-dir /absolute/path/to/binaries`.

**Native file-permission contract:** The native broker opens its pinned local
provider CA using `files::read_private`, and the guest client uses the same
strict reader for the distributed client certificate and CA. These PEM files
are therefore created with `0600` permissions even though certificates
contain public material. Broadening their permissions makes the native process
reject them; changing Rust's private-file validation to accommodate the demo
would weaken the intended production boundary.

The native manifest session validates its broker configuration against the
policy file. In particular, `provider.credential_file` must match
`credential_source.path`; the HTTPS host, pinned address, port, CA and
authentication type must agree too. The standalone lab already supplies these
bindings, and its portable tests compare them against the manifest.

The native disclosure parser also requires **exactly one declaration for every
manifest operation**, even an operation that will be refused by `writes=deny`.
The lab declares a minimal `pr.comment` response projection, while still
requiring that any attempted comment is denied before provider I/O. An early
operator check now rejects incomplete or extra disclosure entries before the
broker starts; the native Rust parser remains authoritative for projection
validity and enforcement.

If the native bridge exits before sending a readiness frame, the script reports
its exit status and a fixed-shape native error code (when one is available).
It never prints arbitrary native stderr, which might contain sensitive paths
or provider information. An `unsafe_file` at this stage typically indicates a
path, ownership, or permissions problem. The full three-binary demo is the
acceptance test; Python-only tests cannot establish native startup success.

**To use the guest client yourself**, launch the session interactively:

```bash
python dev/offline_native_guest.py \
  --interactive --workspace .tools/offline-garrett-manual-01
```

The script prints an actual `garrett-client ... gh pr checks ...` command and
pauses while the Rust broker and provider remain running. Open another terminal
and run it. The guest can also use the three supported `gh pr` read aliases or
`invoke` for named host-approved operations. Return to the operator terminal
and press Enter to revoke the guest, check revocation, and shut down the broker.

For fast portable development feedback:

```bash
python -m pytest -q tests/test_offline_native_guest.py
```

The **authoritative integration check** is the `offline_native_guest.py` command
itself, with all three real Rust binaries present. A passing portable pytest
run is not a substitute. No Rust rebuild is needed if those binaries are
already current; run a normal `cargo ... build --bins` only after Rust changed.

## What actually happens

1. The operator creates a host-only synthetic bearer token, an independent
   throwaway HTTPS CA/provider, and a GitHub PR manifest expanded through the
   project's **normal** `github_pr` preset. The destination is pinned to
   `127.0.0.1:<provider-port>` with a pinned CA and the TLS hostname
   `api.example.org`. The operation set includes a *write* (`pr.comment`), but
   the broker is independently configured `writes=deny`.
2. The **native guest client** generates a software private key and CSR using
   `garrett-client request --key-mode software`. The **native authority**
   verifies the CSR, requires the operator-approved fingerprint, enrolls the
   subject and issues its signed certificate. The guest receives only its
   identity key/certificate, public CA, and subsequently a bound surrogate;
   the real provider bearer token and native authority signing keys remain in
   the host directory.
3. The **native bridge** starts with the host-owned policy, disclosure,
   certificate authority and synthetic credential file. It issues a bound
   surrogate. The guest process calls `gh pr view` and `gh pr diff` over native
   mTLS and receives only an approved view and text diff. The provider records
   three actual credentialed GET requests (one view preflight; one diff
   preflight and one final diff).
4. The guest submits a **real named write** to the broker using `invoke
   pr.comment`; the broker's `writes=deny` returns a structured denial without
   a POST or other additional provider request. This does **not** merely test
   rejection of an unsupported guest-side `gh` alias.
5. The native operator authority revokes the subject while the broker is still
   running. A subsequent guest read is rejected, and the provider sees no
   additional HTTP request.
6. The operator checks the actual provider-observed Authorization header, HTTP
   method and API version, the presence of the host audit, the absence of the
   synthetic bearer token and surrogate from the host audit, and the absence
   of private provider fields and the bearer token from guest distribution
   files and process output. It saves **redacted request observations** and a
   JSON summary if `--workspace` was specified.

A passing run reports `ok: true`, `denied_write: true`,
`revocation_fenced: true`, and an exact list of three provider-observed GETs.
The provider's synthetic token is never printed or persisted to a guest file.
The `guest_distribution_contains_provider_credential: false` field refers to
distributed files only, **not** the guest's OS-level filesystem access.

## Exact limitations

- **Not a VM confinement test.** The demo uses distinct `host/` and `guest/`
  directories under the *same Unix account*. Process cwd and file distribution
  demonstrate which bytes the guest CLI actually needs, but an arbitrary
  malicious process with that account's filesystem privileges could read the
  operator's host directory. To establish real guest custody separation, place
  the already generated guest assets in a separately isolated guest and
  expose only the authenticated broker socket via the intended host/guest
  boundary. Validate that under W8; do **not** infer it here.
- **Not a general `gh` implementation.** Only the native supported PR aliases
  and named manifest operations work. No GitHub credential or real GitHub API
  is contacted; live compatibility is W7.
- **Not formal I/O refinement.** Actual Rust processes are used, but this
  finite witness does not prove complete W3 effect reachability or native-to-Lean
  NR-1/NR-2 forward simulation. W4/W5 proofs retain their stated abstract
  premises. The present unproved obligations are still listed in the
  [active roadmap](planning/aivm-secrets-native-read-assurance-roadmap.md).
- **Synthetic keys only.** No physical TPM or external key attestation. The
  operator is trusted and has host filesystem access.
- The script intentionally terminates the broker at the end and is not a
  daemon supervisor, production enrollment UI, persistent guest relay or
  deployment recipe. The optional saved workspace contains synthetic key
  material: delete it after inspection.

## Next valuable engineering step

With a real operator/guest positive witness in place, implement **NR-1** by
extracting a *production-called* native Rust transition representing dispatch
admission, acknowledged audit, and provider-send permission. Link the exact
extracted source to a focused Lean preservation lemma; do not add a parallel
hand-written transition model and call that Rust refinement. Keep W3/W6
external I/O contracts explicit and the offline guest workflow passing.
