# Native newline framing and reply uncertainty

Status: the [frozen record](../dev/validation/2026-10-18-line-framing.json) binds
`df5542e` to 2,524 portable tests without skips, 296 required workflows in
both build configurations, 360 audited Garrett obligations and six rejected
framing mutations. The nine new obligations cover the scoped validator and its
supporting lemmas; JSON/TLS/stream/native mediation remain separate boundaries.

The native guest client and bridge now use one bounded frame reader. It requires
a terminal newline and rejects bytes already buffered beyond that newline. The
reader retains its `BufReader` through validation; `read_until` by itself can
return a syntactically valid JSON object at clean EOF or hide a coalesced second
frame when its buffer is dropped.

The unchanged Python reference rejected those inputs. Before the fix, the new
ordinary-native process tests reproduced nine failures: three accepted malformed
client replies, three guest request suffixes that still reached the broker, and
three malformed forwarded broker replies treated as completed replies. The
expanded 32-case baseline has 23 passing controls and those same nine
failures; its record hashes the ordinary release binaries before and after the
run. The corrected implementation passes the expanded 32-case peer
matrix, including both Python/native clients at the exact reply limit and one
byte over it. The retained baseline log is
`.tools/line-framing-baseline-expanded.log`, with provenance in
`.tools/line-framing-baseline.json`.

## Observable behavior

- Incoming guest framing errors are `invalid_request` before the bridge calls
  its broker/provider handler. Tests use a valid authenticated identity and
  assert that the restricted provider was not called.
- Once a request has been sent, EOF without newline, malformed JSON, an
  unsupported reply root, an oversized frame or an observed trailing suffix
  gives `outcome_unknown`. There is no automatic retry or claim that the
  original request did not run.
- Complete single frames and frames assembled across partial reads work.
  The byte bound includes the terminal newline. JSON validation remains a
  separate step: an empty line is a complete frame but an invalid JSON reply.
- Only bytes observed in the current read are checked for trailing data. The
  protocol returns after the first complete frame; it does not wait for EOF or
  prove that a peer will never send another byte later. This matches the
  Python reference's observed-suffix contract.

The malformed-ingress regression uses the native bridge's explicit legacy
local-broker backend with Python's restricted broker/provider fixture. The
shared reader runs before backend selection. Existing W2/W6 workflows separately
exercise valid native-provider calls; this is not a proof of every backend's
native I/O behavior.

No wire version, accepted identity mode, credential scope, JSON representation,
provider operation or AIVM integration changes. Existing socket timeouts and the
native absolute watchdog remain in place. This increment does not align every
Python/native handshake error or deadline; the parity claim concerns the named
post-send framing cases.

## Extracted contract

`line_frame::complete(data, buffered, limit)` is production Rust shared by bridge
ingress, forwarded local-broker replies and the native guest client through the
same reader. `proofs/GarrettLineFrame.lean` proves total Boolean equivalence to:

1. `data` has at most `limit` bytes;
2. the observed buffered suffix is empty;
3. there is a payload with no newline such that `data = payload ++ [newline]`.

Corollaries reject any nonempty buffered suffix and any unterminated data, and a
positive witness rules out blanket rejection. The predicate treats payload bytes
as opaque. It proves framing, not JSON validity, authenticated origin, approved
disclosure or confidentiality.

Charon/Aeneas translation, their standard models, the Rust compiler/ABI and Lean
kernel remain trusted. `BufReader`/`Read` behavior, TLS, OS sockets, deadlines,
JSON parsing and actual caller placement are reviewed/tested adapters. The W3
source guard attacks selected bypasses and pins 82 Rust/build files; it is not
transitive reachability or complete native I/O mediation.

Use focused `lake env lean -DwarningAsError=true GarrettLineFrame.lean` from
`proofs/` during proof development. The full audit is `garrett.py record`; the
filtered mutation family is `garrett.py mutate --mutation-filter '^line framing '`.
All peers, keys and credentials in tests are synthetic. No VM or TPM is required.
