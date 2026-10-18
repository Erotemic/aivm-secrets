# Credential-free agent tools and extensible authorization plugins

Status: **proposed direction; not an implemented interface** (2026-10-17).
This document adds a target architecture and work plan. It does not change
existing Garrett wire formats, implemented policy schemas, verification claims,
or this release's operating procedures.

Related decisions and evidence:

- [Provider-neutral integrations](aivm-secrets-agnostic-integrations.md):
  the existing schema-2 service manifest, untrusted CLI translation, typed
  effects, and the stated limitations of transparent stock CLIs.
- [Garrett protocol verification](aivm-secrets-garrett-verification.md):
  credential custody, certificate-bound surrogates, and outstanding full-service
  composition/refinement obligations.
- [Operations policy](aivm-secrets-garrett-operations-policy.md):
  the existing `deny` / `approve` / `allow` write modes and retry semantics.
- [vTPM key policy](aivm-secrets-garrett-vtpm-policy.md):
  key provenance and VM lifecycle conditions, including rollback and cloning.
- [Formal assurance plan](aivm-secrets-formal-assurance.md):
  AUTH-01, EFFECT-01, CONF-01, BIND-01, CODEC-01 and related obligations.
- [Modular proof architecture](aivm-secrets-modular-proof-architecture.md):
  extraction and refinement of source-level Rust controllers.

## 1. Decision and non-goals

**Target:** allow an arbitrary program running in an untrusted AIVM guest to use
an external service *without receiving that service's usable credential*.
Authorization of each credentialed effect is fully automatic under a previously
established host policy. A human approval may be an optional policy mode, but
**must not be necessary for ordinary unattended agent operation**.

The real `gh` executable should eventually work in the guest. Reimplementing
all of `gh` commands as bespoke broker endpoints is not an extensible
architecture. Equally, running arbitrary guest-selected executables with
`GH_TOKEN` on the trusted host is not the default: arbitrary code execution
in the credential-bearing process would expose the token, regardless of
whether that process is inside a container.

The design has three complementary extensibility paths:

1. **Verified, restricted shims:** a small `gh`-shaped command subset (and
   later other tools) translated by a versioned, reviewable, preferably
   source-verified Rust adapter into typed operation requests.
2. **Credential-free stock tools:** real, unmodified `gh` or other tools run
   in the guest, with a suitable client transport integration that sends
   requests to a host-side, effect-authorizing credential gateway.
3. **Operator-defined rules:** users can install their own declarative allow
   policies for service effects and arbitrary *guest* executables. A separate,
   explicitly lower-assurance executor mode may run arbitrary *host*
   executables, but this must not silently inherit the verified-confidentiality
   claim.

**Non-goals:** proving GitHub, the entire `gh` binary, a Linux container,
a TPM implementation, arbitrary user plugins, or arbitrary host programs
correct; arbitrary shell execution as a privileged broker API; automatic
permission escalation when a plugin is installed; claiming provider writes
can always be rolled back or exactly-once retried.

## 2. Placement and trust boundaries

```text
AIVM guest VM (attacker may control the agent and guest user processes)
  agent + arbitrary code + real gh + workspace (possibly virtiofs)
  guest Garrett client; enrolled identity key available through guest TPM API
  surrogate / public grant material; NO usable GitHub token
           |
           | authenticated, certificate-bound Garrett channel
           | typed operation OR mediated HTTP request (future transport)
           v
HOST: trusted Garrett bridge + broker + policy interpreter
  current enrollment / revocation / epoch; signed bound surrogate verifier
  authorization, audit, budgets, typed effect construction
  pinned service destination; provider credential vault / lease
           |
           | credential injection into an authorized *host-created* effect
           v
HOST: pinned HTTPS executor ---- authenticated TLS ----> GitHub API
           |
           +---- bounded and policy-projected reply ----> guest

Optional *different* path, explicitly marked lower assurance:
  trusted host tool-runner -> operator-selected executable -> provider
```

- The **host** owns the broker, issuer/authority, credential resolver, policy
  registry, audit and provider egress interpreter. These components can be
  separate processes without changing which side of the boundary owns them.
- The **guest** owns its arbitrary programs, workspace, and CLI. Virtiofs
  transfers permitted working files, not host credential files, issuer keys,
  vTPM state, or privileged broker sockets.
- For a software vTPM, the virtual device is visible in the guest, while
  `swtpm` and its persistent state are host-managed. A physical host TPM may
  protect host state separately. Neither makes guest users inherently trusted.
- TPM non-exportability of a key does **not** stop malicious guest code from
  invoking a permitted signing operation. Authentication identifies an
  enrolled key-holding environment, not the intent of a particular process.
  Per-process trust needs a further isolation/attestation design.
- Garrett's *existing* `aivs1` inner capability and certificate-bound outer
  surrogate are not replaced. The gateway consumes authenticated authority
  derived from that profile and performs **another** check on every effect.
- Guest egress, host-to-provider routing, and the installation path for host
  plugins must be confined independently. Provider request redirects, DNS,
  custom proxy variables, file reads and child processes must not bypass the
  selected interpreter. This is an operational/OS boundary to test and state
  explicitly, not a property of the Lean core alone.

## 3. Automated `gh` walkthrough

Example request (illustrative PR number and repository):

```text
$ gh pr diff 13861 -R TauCetiProject/TauCeti
```

Beforehand, a host operator provisions the VM identity and issues a grant for
specific GitHub repositories, operations, time bounds, request budgets and
allowed output. The grant is subsequently used without a human prompt.

1. The agent starts the **real** `gh`, or an explicitly selected verified
   `gh`-subset frontend, inside the guest. No usable provider credential is
   available via environment variables, config files or a credential helper.
2. The frontend or transport client authenticates the guest to the Garrett
   bridge. The bridge verifies the actual TLS client certificate, surrogate,
   current enrollment and binding. A copied surrogate without the enrolled
   key's signing operation is insufficient.
3. The broker canonicalizes the request. A verified subset could map
   `pr diff` to the already named `pr.diff` operation. An unmodified CLI
   transport would instead provide an inspectable API request for a service
   policy to classify. Both routes end in the *same* authorization core.
4. The broker checks service identity, resource, operation semantics,
   arguments, grant/scope/epoch/time, output policy, budget, and required
   audit acknowledgments. Metadata preflights and rechecks happen where
   required. Unknown API methods, paths and GraphQL documents fail closed.
5. Only an authorized effect reaches a pinned host egress interpreter. It
   appends the provider credential internally and makes the HTTPS request.
   Remove any guest-supplied provider authentication header and select the
   host credential from the authenticated grant, never from a caller header.
   There is **no** fallback to a generic `CONNECT` tunnel that can carry
   unrestricted authenticated traffic.
6. The gateway bounds, parses and projects the provider response as specified
   by policy, performs supported reflection checks, and returns only the
   allowed result. It never returns raw upstream authentication material.

The real CLI may make multiple API calls for one command. **Every** credentialed
call must be authorized and accounted for independently; admission of the
initial command is not carte blanche for later endpoints. Commands that use
Git transport, local helpers, GraphQL, browser login, extensions, or auxiliary
executables need explicit routing and coverage. Unsupported paths fail
closed, rather than silently getting a host token. Output filtering cannot
prevent leakage of public/authorized information that the guest legitimately
receives, nor does a literal reflection check solve general information flow.

### Stock CLI transport is a research item, not an existing feature

The current schema-2 `cli` table is a **limited guest translator**, not stock
GitHub CLI support. To support the real CLI without reproducing its logic,
prototype and compare at least:

- an explicit HTTP transport hook/fork that forwards an API request to the
  Garrett guest client, leaving all upstream authorization at the host;
- supported CLI transport/socket configuration if its exact behavior is
  audited against the pinned `gh` version;
- a dedicated credential-free local HTTP endpoint with a narrow client
  integration, if the CLI can target it without weakening remote TLS.

Merely pointing an HTTPS `CONNECT` proxy at the host does not make encrypted
paths, headers or GraphQL bodies visible to the broker. TLS interception adds
an additional trust root and larger attack surface; it is **not** the assumed
default. No claim of transparent compatibility is made until real integration
tests cover both REST and GraphQL flows, authentication behavior, redirects,
Git subprocesses and any local CLI credential requirements. If the CLI
requires a token-shaped local setting to operate, any placeholder must be
non-secret, invalid at the provider and never treated as authority by the
broker. Caller-provided authentication headers must not be forwarded.

## 4. A plugin *system*, not arbitrary trusted callbacks

**Plugin** means a host-installed, versioned description of an allowed
interface, not guest-selected Python/Rust code that receives secrets. Keep
these responsibilities separate:

| Layer | Responsibility | Trust / verification |
| --- | --- | --- |
| Guest command frontend | Convert `gh ...` (or another command) to a typed request, or direct a stock CLI to the gateway | Untrusted; correctness improves usability but cannot grant authority |
| Policy plugin data | Name service, accepted request shapes, scopes, fact checks and output projection | Operator-installed; interpreted by one guarded core |
| Verified policy interpreter | Canonicalize and check requests; construct authorized effects with a bound ticket | Source-level Rust/Lean target for **all** accepted plugin data |
| Host effect executor | Consume only valid effects and add credentials at a pinned origin | Small trusted runtime with separate network/serialization refinement |
| Optional host executable runner | Run pinned commands under explicit operator control | Additional trusted surface; *not* covered by the strict gateway claim |

Prefer a **total, bounded declarative policy language** and a single Rust
interpreter (with an Aeneas-friendly pure core) over dynamic in-process
`Box<dyn Plugin>` callbacks. Extensible rules can contain typed commands,
finite routes, typed argument sets, canonical path templates, resource
predicates, body bounds and release projections. Disallow arbitrary side
effects inside policy evaluation. Dynamic code may help prepare proposals,
but cannot mint authority tickets, fetch credentials or bypass the final
interpreter. Pin manifests by content digest and record the accepted policy
version in every admission/audit entry.

The existing schema-2 manifest and `AuthorizedEffect` model are the starting
point. A new interpreter must **extend** that design rather than replace it
with a general raw-HTTP or shell invocation endpoint. Unknown features must
make old parsers reject new manifests rather than degrade silently.

### Profiles with explicit assurance levels

| Profile | User extension | Claim we can reasonably target |
| --- | --- | --- |
| `verified-subset` | Reviewed `gh`-subset (or another fixed frontend) + verified effect templates | Prove mapping and core admission/effect properties for the frozen subset |
| `declarative-custom` | Arbitrary guest executables and operator-authored **typed** service allow rules | Prove generic interpreter confinement *relative to those rules*; the rules' provider-level intent is operator responsibility |
| `gateway-raw-api` | Arbitrary guest executables proposing HTTP requests within supported, explicitly allowed shapes | Same generic confinement theorem if complete request classification and executor refinement hold; otherwise reject |
| `trusted-host-exec` | Operator-pinned arbitrary host executable and argv rules | Operator accepts enlarged TCB and credential-exposure/ACE risk; no generic secrecy proof for the program |

Names above are **proposed configuration concepts**, not implemented CLI flags
or accepted manifest schema. Enabling a weaker profile must require a
host-owned configuration decision and produce an explicit assurance label in
logs and inspection commands. The *guest* must never select or escalate its
own profile by passing a request field.

### Example: a user-defined allow rule

The following pseudoconfiguration is **illustrative**, not currently parsed:

```yaml
policy_version: 3                  # proposed, not current schema 2
service: github
execution: guest-program-gateway   # arbitrary code in the untrusted VM
identity: enrolled-vm
parent_authority:
  repositories: [TauCetiProject/TauCeti]
  permissions: [pull_requests_read]
rules:
  - name: read-pr-diff
    request:
      method: GET
      route: /repos/{repository}/pulls/{pr}
      accept: application/vnd.github.diff
    parameters:
      repository: {one_of: [TauCetiProject/TauCeti]}
      pr: {integer_range: [1, 200000]}
    effect: read
    release: {kind: bounded_text, max_bytes: 1048576}
unknown_requests: deny
```

Here the **host** chooses which service facts and provider semantics the
request template represents. A rule declaring a write-capable endpoint to be
read-only is a bad rule even if its parser has been formally verified. The
example uses the GitHub pull-request route and diff `Accept` media type
already present in this repository's schema-2 example; runtime support for
this new policy format has **not** been implemented. Identity/ownership
preflights still need to be specified and tested as appropriate.

For any accepted policy `p`, let `Grant(g)` be the installed parent scope and
`Effects(p)` the effects described by the policy. The verified core should
ensure a guest request can create only an effect in their intersection, after
current binding, time, budget, audit and state checks:

```text
Emitted(effect, request, state)
    -> AuthorizedGuest(request, state)
    and effect in Effects(p) intersect Grant(g)
    and HasMatchingReservationAndAudit(effect, state)
```

This is an **authorization-relative** theorem. It does not say every effect
in an arbitrary user-authored policy is harmless, that an endpoint called
`read` cannot change upstream state, or that a compromised permitted guest
will not exploit its full granted authority. User policies may deliberately
allow writes or broader resource scopes, bounded by any independent parent
policy the host chooses to retain.

### Allow arbitrary host executables only as an explicit opt-out

Some programs have no usable credential-free transport or typed effect model.
An operator may choose to permit specific commands (or a broader executable
policy) on the host. This is **not** the same as allowing arbitrary code in a
credential-free guest.

- Pin executable identity (path and ideally content digest), command profile,
  argument parser, ownership, effective UID, environment, working directory,
  network destinations, mounts, time and output limits. Never implicitly run
  a shell, search the guest's PATH or inherit guest-controlled config.
- Run in a separate, unprivileged worker (or stronger container/VM) and keep
  issuer, broker and unrelated credentials out of its namespace. These are
  defense-in-depth steps, not proof of secrecy if it still receives a token.
- Prefer a worker that uses the same token-free effect gateway. **If** the
  arbitrary executable receives usable provider credentials, ACE in that
  worker means those credentials are compromised. State that trade-off plainly.
- Distinguish risk accepted by the **host owner** from permissions delegated
  to an untrusted **guest**. A guest cannot promote its own policy into this
  mode. A host operator may opt in without per-request approval.
- An executable's arbitrary stdout/stderr is not necessarily safely
  declassifiable; do not promise `CONF-01` merely from bounded output or
  literal reflection scanning.

## 5. Authorization and noninteractive operation

Provisioning/administrative approval and **per-operation interactive
approval** are different. Enrollment, key rotation or initial grant issuance
may remain host-administered; the normal agent action must not pause waiting
for a human.

- Each VM/session starts with an operator-authorized parent grant and a finite
  budget, expiry and scope. Automatic requests use this grant and fail closed
  when it is absent or insufficient.
- A write may be automatically permitted by a sufficiently narrow **host
  preauthorization**. It still consumes budget, is audited and follows
  conservative retry semantics. Default-deny writes is compatible with
  automation; a prompt is not required for either allow or deny.
- Preserve the existing `deny`/`approve`/`allow` policy modes until a
  versioned migration is specified. The current `approve` mode can remain an
  **optional** interactive mode, but cannot be the only successful path for
  unattended authorized actions. A new policy must never bypass the host's
  independent write authority by reclassifying a write as a read.
- Failures after dispatch, particularly writes with an unknown outcome,
  cannot be silently retried. Reconciliation and any provider-supported
  idempotency contract must be modeled explicitly.
- Expiry, revocation and re-enrollment require fail-closed behavior. Existing
  vTPM/enrollment lifecycle documents do **not** yet promise unattended
  renewal; automatic lifecycle management is separate future work, not a
  hidden side effect of invoking `gh`.

## 6. Verification and trust ledger

The important target is **confinement for any admitted plugin policy**, not a
one-off theorem about the spelling `gh`. Suggested additional obligations,
orthogonal to the existing Garrett/W-series work:

| ID | Required result / evidence |
| --- | --- |
| TOOL-01 | Total canonical parser for versioned policy data; malformed, ambiguous or unknown rules fail closed, including HTTP request smuggling and schema downgrade |
| TOOL-02 | For all installed declarative plugins, the only way to construct a credentialed effect is via the verified admission/ticket/effect interpreter |
| TOOL-03 | Every emitted effect is within the authenticated grant, host-selected service rules, resource bounds and current time/epoch/budget, with required audit acknowledgment |
| TOOL-04 | A verified `gh` frontend maps its *specified* accepted command subset to the intended typed operations and rejects everything else; it cannot extend authority |
| TOOL-05 | The credential source and executable's upstream auth header are inaccessible to the guest; output/errors/metadata obey the stated release projection and observation model |
| TOOL-06 | The concrete HTTP/TLS/serialization executor emits exactly the approved destination, method, headers, path and body; redirects, DNS, proxy settings and multi-call flows do not create alternate credentialed effects |
| TOOL-07 | Custom declarative plugin installation cannot mutate parent policy, issuer state, or the ticket constructor; plugin revisions are pinned and reflected in audit and revocation decisions |
| TOOL-08 | Optional host executable mode is segregated, explicitly selected by the host, and never reported as covered by TOOL-05 or TOOL-06 without program-specific evidence |
| TOOL-09 | At least one permitted `gh` command successfully obtains a permitted result, and denied commands do not reach the provider (exclude vacuous deny-all proofs) |

Two possible proofs must not be conflated:

1. **Generic interpreter theorem**: for *any valid plugin data*, the trusted
   core emits only effects authorized by that data and the host's parent
   policy, under explicitly stated model assumptions.
2. **Service/command semantics theorem**: an accepted `gh pr diff` request
   really denotes the intended GitHub read and produces the agreed public
   projection. This depends on the command adapter, provider API contract,
   response processing and implementation correspondence. A custom plugin
   gets no such theorem automatically.

Prove the pure sequential Rust decision code using the established
Charon/Aeneas -> Lean pipeline where possible. Do not model an arbitrary
plugin as a powerful Lean oracle that can fabricate an `AuthorizedEffect`.
Use finite data structures and a single interpreter; test generated adapters
against reference traces and positive/negative witnesses. Concrete TLS,
client key custody, HTTP libraries, vTPM, filesystem, native I/O,
configuration load and process isolation remain separate refinement or
assumption obligations. W4/W5 modeled trace results, if present in a newer
working tree, do not themselves discharge runtime correspondence (W6).

**Claims to avoid:** "safe to run any code with a provider token", "a
verified policy parser verifies the human intent of an arbitrary policy",
"sandboxing prevents token extraction from a compromised worker", and
"no credential leak" when arbitrary response encodings, side channels,
write effects or uncontrolled host executables remain outside the model.

## 7. Implementation sequence and tests

This is a new **tool integration workstream**, not a renumbering of the active
W0-W8 Garrett security plan. Each stage should have a demonstrable
failure/success test before being treated as implemented.

1. **T0 — contracts:** freeze the guest-to-gateway request envelope,
   authenticated actor/grant association, desired supported effects,
   output types, and strict/relaxed assurance labels. Compare with the
   existing schema-2 operation and Garrett surrogate formats; do not
   fork common parsers or quietly weaken the current broker.
2. **T1 — interpreter and plugin data:** specify a versioned declarative
   adapter grammar, canonical hashes, typed resource checking and error
   behavior; support a user-authored policy installed by the host. Reject
   invalid policies before any credential is acquired.
3. **T2 — verified `gh` subset:** implement/extract a small Rust mapping for
   `pr view` / `pr diff` (or the current covered subset), prove accepted
   arguments lead to exactly the permitted typed effects, and test
   disallowed forms such as `gh auth token`, arbitrary `gh api`, extensions
   and injected options. Reuse the current manifest-based `gh` frontend
   while migrating; keep old client behavior stable.
4. **T3 — generic HTTP gateway:** introduce a guest-usable transport with
   **no provider token in guest memory or files**. Prove/check each
   request's effects independently, including multi-request commands,
   header sanitation and output projection. Test with hostile
   requests, response redirects, TLS errors and forged headers.
5. **T4 — real `gh`:** evaluate an actual `gh` transport integration,
   freeze supported `gh` version and verbs, and demonstrate a real
   `gh pr diff` through the gateway with no real GitHub token in the VM.
   Reject unsupported Git transport and GraphQL requests, rather than
   forwarding them uninspected.
6. **T5 — operator extensions:** validate custom declarative route policies
   and arbitrary *guest* tools; add an explicit `trusted-host-exec` profile
   only with resource/credential containment, audit and a visible assurance
   downgrade. Test that guests cannot install or select privileged policy.
7. **T6 — composition:** connect the extracted decision proofs, Garrett
   issuance/binding, transport effects, AIVM vTPM lifecycle and live-VM
   network confinement. Record precise gaps and assumptions instead of
   claiming whole-system soundness from a successful Lean build.

Minimum end-to-end fixtures:

- A VM with virtiofs runs a real or restricted `gh` command; the host receives
  an authenticated Garrett request, sends the allowed GitHub API effect and
  releases only the permitted answer **without** a per-request prompt.
- Malicious guest code reads its entire reachable filesystem/environment,
  invokes the TPM signing oracle, modifies the CLI, submits arbitrary HTTP
  paths/headers/GraphQL, and replays a surrogate: no usable provider token
  appears, and no effect outside its grant is dispatched.
- A policy author installs a wider **declarative** rule; only that rule's
  allowed extra effects become possible and the proof claim remains
  explicitly relative to its policy. A guest cannot install that rule.
- Opting into an arbitrary host executable triggers a distinct, inspectable
  assurance profile. A test that compromises that worker must be treated as
  exposure of any credential supplied to it, not as a pass for confinement.
- Failures across issuance, audit, preflight, cancellation, renewal, expiry,
  revocation and transport disconnect do not silently retry potentially
  completed writes or relabel uncertain outcomes as definite denials.

## 8. Open design decisions

1. How exactly should stock `gh` obtain a credential-free transport that
   covers REST/GraphQL without requiring a complete fork or unsafe TLS
   interception? Investigate against a *pinned* actual CLI version.
2. Which semantic authority should custom allow rules specify: HTTP routes,
   provider-specific typed operations, or both with a mandatory checked
   refinement? Prefer typed operations for high-assurance profiles.
3. Can the trusted broker use short-lived, repository-scoped provider
   credentials and per-request leases instead of a broad long-lived token?
   Provider semantics and refresh ownership must be reviewed.
4. How should untrusted responses be projected to stdout/stderr for stock
   tools while maintaining a useful CLI experience without generalizing
   the permitted disclosure set accidentally?
5. Should a sandboxed host executor with **no** provider credentials be an
   intermediate compatibility mode, or can we keep all arbitrary execution
   inside the guest? No host-exec fallback should be automatic.
6. How should host-managed noninteractive grant renewal coexist with the
   existing operator-only enrollment/rotation lifecycle? Keep these concerns
   separate until the identity design explicitly supports automation.

Success means the agent can use useful tools autonomously while the host can
state **exactly** which provider effects were possible, which information was
released, and which parts of those claims are proved rather than assumed.
