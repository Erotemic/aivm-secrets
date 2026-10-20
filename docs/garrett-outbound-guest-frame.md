# Native outbound guest frame

The authenticated native bridge now uses the production
`aivm-secrets-garrett-core::guest_frame` encoder and single-attempt writer.
This advances NR-2/3's outbound byte and attempt boundary. Selected JSON value
origin, native TLS correspondence and connected adaptive histories remain open.

`GuestFrame::from_answer` retains the existing canonical JSON representation and
fixed `tls::failure` mapper. It prepares the complete wire before any application
write: the existing reply bound includes the appended terminal newline, and the
shared `line_frame::complete` rejects an internal newline. An oversized encoded
reply closes without sending an application frame. If the request already ran,
the client still reports post-send uncertainty; this does not authorize retry.
The opaque encoder itself accepts an empty payload when it fits. JSON validity
is a separate adapter condition.

`Frame` owns private wire bytes and an attempt bit. Its actual `send` marks the
attempt before calling the writer and refuses every subsequent call. The native
`GuestWriter` passes that exact buffer through `Write::write_all` and `flush`.
A zero-byte failure, partial submission or flush error retains the attempt;
none implies that the guest received a complete frame. `write_all` can perform
multiple underlying writes, so one application attempt is not one syscall or
one TLS record. Close-notify/transport flushing remain in `Bridge::serve`.

Nine named obligations in `proofs/GarrettGuestFrame.lean` cover the extracted
production functions: total exact admission, bounded unchanged payload plus one
newline, a positive witness, returning callback/error/state equivalence,
preparation-to-writer composition, and refusal after a returned failure. The
proof handles every modeled payload and limit, including the vector-push bound;
it assumes no successful writer result merely to prove admission. Callbacks
that diverge or fail in the extraction model do not become returned Rust errors.
The extracted functional model returns mutable post-state with the callback;
Rust source ordering and safe ownership establish mark-before-call placement.
These returning proofs do not establish non-returning, panic/unwind or drop I/O.

The native fault-writer tests exercise the real adapter with zero-byte, partial,
flush-error and successful outcomes, escaped newlines, Unicode, fixed errors,
and oversized output. Re-extracted source mutants target the bound, delimiter,
internal-newline validation, retry guard, attempt mark and substituted wire.
The W3/W6 source guards check selected caller bypasses; the reviewed W3 inventory
now contains 96 Rust/build files, not exhaustive transitive I/O evidence.

During development, compile only this leaf from `proofs/`:

```sh
lake build +GarrettLineFrame
lake env lean -DwarningAsError=true GarrettGuestFrame.lean
```

The central `GarrettCheck` audit includes the nine names. Reproduce exact
Charon/Aeneas extraction and the full audit with `garrett.py record`; target the
six new mutants with `garrett.py mutate --mutation-filter '^guest framing '`.
Compiler, extraction/standard models, TLS/OS/Write behavior, canonical JSON,
selected-value provenance and full service mediation retain their stated trust
or open obligations. No protocol version, dependency or credential scope changes.

The [frozen acceptance](../dev/validation/2026-10-20-guest-frame.json) pins source
`29ddf1e`: 3,029 full cases without skips, 530 named axiom audits, 767 release
parity cases, 74 Rust workspace cases, all six new typed/extracted mutations,
both native build modes, six safe installed-vTPM workflows and packaging with
all 270 source pins and the embedded Garrett manifest byte-identical. The first
concurrent run's one-second grant startup failure is retained; the unchanged
isolated case and final full rerun pass. No expiry condition or timeout changed.
