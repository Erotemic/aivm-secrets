# Guest protocol, version 1

This is the wire protocol between a guest client and the native broker
(`garrett-bridge`), as implemented at the commit that last edited this file.
It is what a release of the read-only profile promises to keep stable.
Process contracts for integrators are separate:
[native session](aivm-native-session.md) and
[HTTPS proxy profiles](https-proxy-profile.md).

## Transport

- A Unix stream socket that the host forwards into the guest (AIVM uses an
  SSH reverse forward, mode 0600 in the guest).
- TLS 1.3 only, with mutual authentication. The guest presents the client
  certificate that `garrett-authority` issued for its enrolled key. The
  bridge verifies it against the session CA and the identity registry.
  Session resumption and early data are disabled.
- One request per connection. The client sends one frame, the bridge sends
  one frame and closes the TLS session.

## Frames

A frame is one JSON object followed by a single `\n`. A request frame is at
most 65,536 bytes including the newline. A reply frame is at most
2,162,688 bytes (2 MiB of body plus 64 KiB of envelope). A missing newline,
trailing bytes or an oversized frame is a protocol error. The client must
treat it as `outcome_unknown` if it had already sent a request.

## Requests

Every request has `version` (the integer `1`), `capability` (the bound
capability string the guest was given) and exactly one verb. Unknown keys are
refused.

| Verb | Form | Effect |
| --- | --- | --- |
| `request` | `{"version":1,"capability":C,"request":{"operation":NAME,"arguments":{...}}}` | Run one named operation from the host manifest with typed arguments |
| `describe` | `{"version":1,"capability":C,"describe":true}` | Return the operation names and the write mode. No provider contact |
| `renounce` | `{"version":1,"capability":C,"renounce":true}` | End this grant now. Audited. No provider contact |

A write may carry `"idempotency_key":KEY` next to `operation` and
`arguments`. It is required for writes in a coordinated deployment and for
operations whose manifest declares an idempotency header, and refused on
reads. It is transport metadata: it never changes what is authorized.

`delegate` is reserved and always refused by the native broker.

## Replies

Success:

```json
{"ok":true,"result":RESULT,"version":1}
```

`RESULT` contains only the fields the host's disclosure contract selects.
Paginated reads add
`"meta":{"pagination":{"page":P,"per_page":N,"possibly_more":BOOL}}`. `describe` replies
`{"description":{...},"ok":true,"version":1}`, and `renounce` replies
`{"ok":true,"renounced":true,"version":1}`.

Failure is always one of these fixed lines, keys in byte order, so a
failure carries no data beyond its code:

```json
{"error":{"code":CODE,"message":MESSAGE},"ok":false,"version":1}
```

| Code | Meaning for the client |
| --- | --- |
| `invalid_capability` | Capability or identity not accepted (expired, revoked, wrong peer, tampered) |
| `invalid_request` | Malformed or unsupported request |
| `denied` | The operation or its arguments are outside the grant |
| `revoked` | The grant was revoked |
| `expired` | The grant has expired |
| `exhausted` | A request limit was reached |
| `invalid_policy`, `resource_mismatch` | Host configuration problem |
| `unreachable` | The provider could not be reached; nothing was sent |
| `upstream_response`, `upstream_rejected`, `upstream_error` | The provider answered with an unusable, rejected or failed response |
| `outcome_unknown` | A request may have reached the provider. Do not retry automatically |
| `credential_source` | The host credential is missing or invalid |
| `unsafe_file` | A host file failed its ownership or permission check |
| `internal_error` | The broker failed closed |

The broker proves the reply forms (`production_read_frame`,
`denial_frame_exact`); see the [proof tour](assurance/native-read-proof-tour.md).

## Versioning

- `version` stays `1` for as long as every v1 request keeps its meaning.
- New verbs, new optional reply fields and new error codes may be added
  within v1. Clients must ignore reply fields they do not know and must
  treat an unknown error code like `internal_error`.
- Removing a verb or field, changing what a field means, or changing the
  frame limits needs `version: 2`. The broker then refuses `version: 1`
  with `invalid_request` rather than reinterpreting it.
- The session identity (certificate and capability) never upgrades in
  place. A new version means a new session.

## Retry rules

A client may retry `invalid_request`, `denied` and `unreachable` after
changing something. It must never retry automatically after
`outcome_unknown` or after a transport failure once the request frame was
written. The same rule holds inside the broker: a write whose outcome is
uncertain is never sent twice.
