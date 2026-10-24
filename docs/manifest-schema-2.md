# Manifest schema 2 (frozen)

A host manifest says which named operations a session may run against one
HTTPS service, with which arguments, and what each operation sends. This page
fixes schema 2 as a compatibility promise. Frozen 2026-10-24. This was an
agent decision that the maintainer can revisit; it records what the parsers
already accept and adds no features.

The normative parsers are `aivm_secrets/kernel/https.py` (Python reference)
and `rust/crates/aivm-secrets-garrett/src/manifest.rs` (native). The
[operator guide](source/secrets.rst) explains how to write a manifest, and
[`docs/examples/`](examples/) holds complete ones.

## What is frozen

Every object below accepts exactly the listed keys. A missing required key,
or any other key, makes the manifest invalid (`invalid_policy`). Nothing is
inferred from a key that is absent except the defaults stated in the operator
guide.

| Object | Required keys | Optional keys |
| --- | --- | --- |
| Manifest | `schema` (= 2), `adapter` (= `https`), `service`, `host`, `authentication`, `credential_source`, `operations` | `egress`, `headers`, `checks`, `cli`, `lifetime_seconds`, `max_requests`, `max_body_bytes` |
| Operation | `name`, `effect` (`read` or `write`) | `method`, `path`, `parameters`, `query`, `body_fields`, `response`, `accept`, `requires`, `returns`, `defaults`, `fold`, `page`, `graphql`, `idempotency_header` |
| Check (in `checks`) | `path`, `require` | `accept`, `bind` |
| Check requirement | `at` and exactly one of `equals`, `equals_parameter` | `fold` |
| Capture (in `bind`) | `at`, `format` | — |
| Body field | `max_bytes` | `optional` |
| Pagination (`page`) | `size` | `at`, `parameter` |
| GraphQL (`graphql`) | `document`, `operation`, `variables` | — |
| CLI row (in `cli`) | `command`, `operation` | `positional`, `options`, `output`, `json_fields`, `json_at`, `json_list`, `repository_default`, `json_alternative`, `json_rules`, `json_complete` |

`cli` is guest-side presentation for the Python client and carries no
authority. The native broker refuses a manifest with a non-empty `cli`
table, and the native client has its own closed command table.

## What each manifest means

- The **digest** of a manifest is the SHA-256 of its canonical normalized form
  (`parse_policy(...).to_dict()`, keys sorted). Two manifests with the same
  meaning have the same digest; a schema-1 shorthand and the schema-2
  manifest it expands to are the same policy. The digest is bound into every
  grant, approval and audit record.
- An operation's **effect class** is what it declares, never inferred from
  the HTTP method: a `GET` can change state.
- A **write** that has been handed to the provider and then fails is
  `outcome_unknown`, never "rejected", unless a future schema adds a
  provider contract that says otherwise.

## How it may change

- Schema 2 manifests keep their meaning and their digest. A parser change
  that would accept a schema-2 manifest with a different meaning, or change
  its digest, is not allowed.
- New presets and new example manifests are additions, not schema changes.
  Adding an operation to the GitHub preset (as `pr.statuses` was on
  2026-10-24) changes nothing for policies that do not list it.
- New keys, new effect classes or new semantics need `schema: 3`. A schema-3
  parser keeps accepting schema 2 with unchanged meaning and digest. A
  schema-2-only broker refuses `schema: 3` rather than guessing.

## What this does not promise

That a manifest is correct for its service. Whether an operation marked
`read` really has no side effects at the provider, and whether the selected
fields are safe to release, is a review of each manifest (`SPEC-01`,
`SPEC-02` in the [assumption ledger](planning/aivm-secrets-assumptions.json)).
