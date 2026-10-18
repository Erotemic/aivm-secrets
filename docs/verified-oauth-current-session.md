# Native OAuth refresh without session restart

An explicitly refreshed access token is now used by the next request in the
same native account or manifest session. The guest capability, TLS listener,
process and grant deadline stay unchanged. This follows Python's
`OAuthVault.current_lease` contract; it does not add guest-triggered refresh.

The old native session retained the startup access token and rejected any
replacement. Two real TLS regressions reproduced that denial on the baseline.
The native session now seals a random opaque marker, authenticated to the
vault, provider profile, subject and enrollment epoch. Its private credential
opener validates that marker and returns the current access token to the
existing extracted request controller. The HTTP interpreter does not substitute
another credential after admission. The persisted vault schema is unchanged.

A request holds the vault lock across current-token selection, preflight,
final provider emission and reply projection. Participating refresh and
revocation writers wait for that complete operation. Each provider emission
checks both the held token's expiry and the original session/outer deadlines
after TLS setup. Refresh cannot extend those deadlines. Revocation and
re-enrollment invalidate the captured epoch, even when the new token bytes
are identical. Invalid or unavailable custody never falls back to a file.

## Incremental formal scope

The 22-line Rust `require_current_lease` guard reuses `require_lease`, pinning
the captured epoch while selecting generation/expiry from current custody.
Its fresh Aeneas translation is checked by seven additional lemmas in
`GarrettOAuth.lean`: exact acceptance conditions, revoked-session refusal,
re-enrollment fencing, unsettled/expired refusal, generation independence and
a renewed-generation success witness. The older snapshot-lease theorem still
holds for callers using that stricter pure primitive. It no longer describes
the broker's current-token contract.

These are properties of extracted decisions. HMAC, entropy, authenticated
vault decoding, lock participation, concrete opener correspondence, clock
sampling and I/O remain adapter premises under `OAUTH-RUST-01` and
`EMISSION-RUST-01`. The W3 guard and its negative edits check selected call-site
structure, not exhaustive transitive reachability. W4/W5 compile against the
regenerated model without changing their theorem bodies or exclusions. This
increment is not a whole-service confidentiality or concurrent-filesystem proof.

## Automated runtime coverage

`tests/test_rust_oauth_current_session.py` exercises real native processes and
recording synthetic HTTPS providers:

- Account and manifest requests use a successor after explicit refresh in the
  same process with the same capability; Python independently reads that
  successor under the same epoch. No guest request calls the token endpoint.
- Both profiles continue beyond the initial token's expiry after refreshing;
  the configured grant lifetime remains fixed.
- Re-enrollment, token expiry during TLS setup and the original session expiry
  all deny without provider HTTP, for both profiles.
- Refresh waits while a checked request spans preflight and final dispatch;
  both phases use one token, and the next request uses the successor.

A Rust unit test rejects vault, provider, subject, marker and epoch substitution.
Existing vault interoperability, ambiguous-refresh and late-dispatch regressions
remain part of the gate. Tests use synthetic credentials, never live accounts.

```bash
python dev/verification/system.py --proofs --full-tests
python dev/verification/garrett.py record
python dev/verification/garrett.py mutate --mutation-filter 'current session|OAuth stale epoch|OAuth expired lease'
```

The filtered command is a selected mutation run, not the full campaign.
Same-session rollover closes a specific CORE-06 usability gap. It does not
establish all-input Python/Rust parity. Native durable coordination, global
write reservation/idempotency and bound certificate/JWT renewal remain separate
open contracts in the core parity catalogue.
