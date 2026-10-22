# 2026-10-21: OUT-2 adversarial native VM acceptance extension

The maintainer's prior `b21e212` native KVM run on `aivm-2404` passed the
original smoke (14 fixture tests, 3 synthetic authorized GETs). This change
keeps that mode and adds opt-in `--adversarial`: bounded host gateway canary,
actual out-of-scope native read, pre-boot enrolled same-CA wrong-subject identity,
certificate/key mismatch, tampered JWT, guest mount metadata inventory and
forward teardown/reconnect with reauthorization and revocation.

No production Rust, Lean, firewall, AIVM or live credential changes.
The synthetic provider and host-side observations remain the authority for
whether rejected actions caused any credentialed provider request. An extra
permitted read after socket restoration changes expected provider count to
four **only** in adversarial mode. The fixture fails rather than silently
skipping an unavailable prerequisite or forbidden-path probe.

Portable Python tests and W0/W3 boundary guards run locally in the author's
container. A new real-VM run with `--adversarial` remains required before
updating OUT-2 evidence. This is not a proof of exhaustive filesystem
isolation, whole-service information flow, or guest restart/clone behavior.
