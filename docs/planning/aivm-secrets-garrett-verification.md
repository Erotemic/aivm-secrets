# Garrett protocol correctness and credential confidentiality

Status: **acceptance contract with an initial implementation, 2026-10-16**.
See the [Rust implementation and exact proof scope](../verified-garrett.md)
for checked controllers, symbolic secrecy, real TLS/TPM tests and remaining
obligations. The full composed service result below remains open.
The initial [Rust-owned provider profile](../verified-provider.md) adds
credential custody, real HTTPS substitution and a conditional two-run release
proof for `profile.read`; it does not close the general service obligations.
The [composed request controller](../verified-composition.md) now joins actual
outer/inner opening, authorization, exact audit acknowledgement and execution
under named adapter contracts. Finite issuance/use histories, concurrent
revocation boundaries, concrete adapter refinement and general policy support
remain open; this does not close the full-service acceptance items below.
The [issuance/history layer](../verified-history.md) adds acknowledged native
issuance, ideal signature origin over adaptive attacker traces and conditional
source-controller history correspondence. Refinement from actual service I/O
and storage histories to those models remains open.
The [Rust certificate enrollment layer](../verified-enrollment.md) adds actual
CA/CSR signing adapters and extracted key/authority approval proofs, including
TPM-to-CSR SPKI binding. Durable authority administration, registry installation
and physical AK trust provisioning remain open.

The first substantial verification target is the Garrett protocol implemented
by this project:
authorized credential use without giving the agent the credential, and rejection
of an outsider holding a stolen surrogate token. These protocol properties are
open at full-service scope. The existing
[freshness proofs](../verified-freshness.md) establish the extraction pipeline
and reusable lemmas, not this result.

This priority supersedes a budget-first proof campaign. Existing request limits
and authorization rules remain unchanged; their independent proofs are not
prerequisites for starting this campaign. This plan refines CONF-01, BIND-01 and
EFFECT-01 in the [assurance plan](aivm-secrets-formal-assurance.md).

## 1. The result we want

An agent can perform an authorized provider action through the broker while
the actual provider credential remains inside the trusted broker and intended
provider path. An outsider who can reach the broker and copy everything the
agent can export, including its surrogate token and public certificate, cannot
use that token independently without access to the enrolled private key's
signing operation. TPM custody strengthens that last condition when enrollment
actually verifies the key's provenance and restrictions.

Correctness has three parts, all required:

1. **Successful authorized use.** A correctly enrolled client, a valid issued
   surrogate, a permitted request and a healthy provider produce the intended
   request and allowed public result. Refusing every request is incorrect.
2. **Authentication of use.** Every credentialed dispatch has a matching
   issuance, authenticated client connection, current enrollment and allowed
   request. A stolen surrogate alone cannot establish that connection.
3. **Credential confinement.** Raw provider credentials, refresh tokens,
   decryption/signing keys and unwrapped inner capabilities do not enter
   agent-visible replies, diagnostics, audit output or agent-owned files.
   Provider credentials may enter only their designated provider authentication
   path; issuer and broker keys never enter that path.

The final statement must identify the implementation commit, supported profile,
observable outputs, permitted disclosures and each assumed boundary. Protocol
correctness does not establish that an authorized agent uses its actions wisely.

## 2. The protocol profile to implement and prove

Garrett's [proposal](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/)
acquires credentials at the broker, encrypts them inside signed surrogate
tokens, and binds surrogate use to a client certificate through mutual TLS.
This project's current profile has an extra envelope and stateful authorization:

```text
trusted credential acquisition
  -> broker seals provider credential and broker claims into aivs1
  -> issuer seals aivs1 inside the signed certificate-bound surrogate
  -> agent receives the surrogate
  -> agent presents it on a certificate-authenticated TLS connection
  -> verifier checks signature, claims, peer binding and current enrollment
  -> verifier opens the authenticated outer ciphertext
  -> broker opens aivs1 and authorizes the named operation
  -> executor adds the provider credential on the approved provider connection
  -> broker releases only the specified public result
```

Prove this nested profile as implemented. A direct-token profile would require
its own contract and compatibility decision. Do not silently replace formats,
remove the inner reference monitor, or claim general JWT/JWE interoperability.

The versioned profile must freeze these details before the Rust port:

- Exact canonical JSON, base64url, accepted fields, bounds and rejection rules.
- Ed25519 signature over the exact encoded header and payload, with pinned
  algorithm, token type and an enabled issuer key ID selected from trusted state.
- AES-GCM outer envelope with signed public claims as domain-separated
  associated data; the existing inner envelope has its own key and domain.
- Issuer, audience, subject, certificate thumbprint, enrollment epoch, issuance
  and expiry semantics. Public claims are not themselves secret or authority.
- Actual peer certificate DER from the completed TLS handshake. A certificate,
  thumbprint, subject or authentication flag from request JSON proves nothing.
- The source and synchronization of current enrollment and enabled trust keys.
- The permitted broker verbs. The present identity bridge refuses delegation
  because a returned unwrapped child capability would bypass identity binding.

Certificate binding follows [RFC 8705 section 3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3):
the resource server obtains the certificate from TLS and compares it with the
token's binding. The profile requires TLS 1.3 client authentication and excludes
early data and resumption initially; [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-8)
does not supply general replay protection for early data. The token's `jti`
does not currently make application requests one-shot. An authenticated client
can reuse a still-valid surrogate subject to the broker's ordinary policy.

## 3. Adversaries and the conditions on secrecy

| Party | Powers included in the model | Boundary required for the claim |
| --- | --- | --- |
| Malicious agent | Arbitrary requests, malformed bytes, export of its complete readable state, repeated calls, attacker-selected arguments | It cannot read or modify broker memory, keys, runtime, secret files or privileged sockets |
| Network outsider | Reach the identity endpoint, steal surrogates and public certificates, replay traffic, create its own keys, hold another enrolled identity | It cannot forge the intended client's authenticated connection or use that client's signing operation |
| Compromised authorized instance | Use its own permitted signing operation and relay work for someone else | Credential confinement still applies; independent-use prevention excludes access to this live oracle |
| Intended provider | Receive the actual provider credential and process authorized actions | It is trusted not to disclose the credential or deliberately encode it into public results |
| Host and issuer administrators | Configure trust, enroll identities, acquire credentials and control the broker host | They are trusted for this profile; compromise invalidates the relevant custody/authentication assumptions |

A TPM can prevent export of a key without preventing an authorized process
from using it for someone else. The outsider theorem therefore assumes both
key non-exportability and no access to an authorized signing/client oracle.
Protecting against a compromised authorized instance impersonating itself
requires a further process-isolation or attested-workload design.

Use separate adversary experiments: confidentiality allows a fully malicious
authorized agent to invoke its key; stolen-token resistance denies the outsider
access to that victim's signing/client oracle. An adversary allowed to control
the authorized agent cannot simultaneously be forbidden from requesting its
authorized actions. A forwarded TLS byte stream remains a connection to its
authenticated endpoint; it does not authenticate the relay as a new instance.

The initial theorem is parameterized over key-custody profiles until the first
deployment is selected:

- **Physical TPM:** verify trusted endorsement/attestation provenance and the
  enrolled signing key's attributes. State explicitly which host software can
  invoke the key. Physical TPM custody alone does not identify an agent process.
- **VM vTPM:** trust the host/hypervisor and its custody of emulator state.
  Guest non-exportability does not prevent a host administrator from copying
  the vTPM. Existing [vTPM policy](aivm-secrets-garrett-vtpm-policy.md) describes
  the proposed enrollment evidence; it is not implemented assurance.

The [TCG key and attestation specification](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)
describes the relevant key attributes and certification. A CSR signature alone
does not establish that a key was generated inside the intended TPM.
Enrollment must bind checked key evidence, a fresh challenge, the CSR public
key and the intended subject. The broker cannot prove this by trusting a guest
field named `tpm_backed`.

## 4. What secret non-disclosure means

Use two complementary formal statements. First prove that secret-bearing
values reach only approved sinks. Then prove that changing secret contents
cannot change the public protocol trace except through explicitly permitted
disclosures. The second is a relational information-flow property, covering
encoded and indirect leaks that a substring search misses.

Define the observations before proving equivalence:

| Observation or sink | Treatment |
| --- | --- |
| Replies, errors, logs, audit records, agent files and child-process arguments/environment | Public; no secret-bearing values or secret-derived diagnostic text |
| Surrogate and inner-envelope ciphertext visible to the agent | Ideal opaque ciphertext in the symbolic theorem; computational confidentiality needs cryptographic assumptions and correct nonce handling |
| Public identity claims, token/frame lengths and response status | Explicit public metadata in the initial profile; lengths are not promised hidden |
| Approved provider result | Released by a named operation's reviewed response contract, including allowed fields and transformations |
| Provider authentication field on the designated authenticated connection | Permitted release of that provider credential only |
| Host secret storage, crypto state and TPM private state | Trusted private state, subject to separately recorded OS/storage/custody assumptions |

For equal public inputs, public metadata and permitted provider disclosures,
prove equivalent modeled public observations across two secret stores. This
does not claim ciphertext bytes remain identical when the secret changes.
The concrete encrypted observation needs a separate computational argument.
The initial observer excludes timing, microarchitectural effects and privileged
host memory inspection. Those exclusions belong in the claim, not hidden in
an implementation detail.

Permitted disclosure cannot mean arbitrary provider output by definition. Each
operation needs a reviewed response contract that prevents credential-export
operations, credential-bearing URLs and diagnostic/header reflection. An
allowlist of fields alone cannot stop a malicious provider from encoding the
credential inside an allowed string; trust in the intended provider remains
necessary. Returning arbitrary provider JSON/text must be recorded as a broader
disclosure assumption until a server-side response contract replaces it.

Do not define secrecy as absence of the credential's literal bytes everywhere:
an agent may guess or supply those bytes itself. Track information originating
from private state and cryptographic recoverability under the stated attacker
model. The present exact-string reflection tripwire is a useful test defense,
not the intended theorem. It also makes rejection depend on a comparison with
the secret: an attacker who controls reflected content can test guesses. A
strict observation-equivalence proof must account for that branch. Decide
whether to specify bounded guessing under cryptographic entropy assumptions or
replace secret-dependent filtering with a stronger public response contract;
do not declare this leak absent or silently alter Python parity semantics.

## 5. Named obligations and proof boundaries

These are proposed theorem identifiers, not checked Lean declarations.

| ID | Required statement |
| --- | --- |
| GARR-ISSUE-01 | An issued surrogate binds the selected credential authority to the intended enrolled subject/certificate, audience and bounded lifetime; its signed bytes and associated data agree |
| GARR-USE-01 | Every dispatched credentialed operation has a matching accepted issuance, actual authenticated peer, current enrollment/trust generation and request authorization |
| GARR-THEFT-01 | In any reachable protocol trace, an outsider who learns the surrogate and public certificate but lacks the enrolled signing operation cannot cause its independent use |
| GARR-CONF-01 | Protocol transitions preserve secret confinement and public observation equivalence under the declared disclosure policy |
| GARR-ROUTE-01 | Substitution places only the selected provider credential in its designated authentication field on the intended authenticated provider connection |
| GARR-LIVE-01 | Valid enrollment, token, request and successful boundary responses admit a complete successful execution with the specified public reply |
| GARR-REFINE-01 | The extracted Rust protocol controller and its concrete wrapper composition implement the specified transitions and observations |

GARR-USE-01 is a correspondence theorem: a dispatch implies earlier matching
events, not merely that some token fields equal some function arguments.
GARR-THEFT-01 additionally requires a model of attacker knowledge and the
unforgeability of authenticated channels. GARR-CONF-01 requires reasoning about
the envelope and output path, not merely a kernel with no secret parameter.

Model a network attacker who can compose, observe and replay public messages,
create its own keys and identities, and request allowed operations. It cannot
decrypt or sign without the corresponding authority. Prove the symbolic
secrecy and correspondence results in Lean over all finite traces of this
model. Quantification over all traces is essential; enumerated tests are
supporting evidence.

Connect actual Rust to that model with Aeneas extraction. Model crypto, TLS,
storage and TPM actions as explicit operations with input/output contracts;
only their trusted adapters may create verified evidence. Check exact signed
bytes, associated data, nonce selection and call ordering in the wrappers.
Accepting a caller-supplied `signature_valid: true` as the authentication model
would leave the decisive implementation obligation unproved.

The first extraction spike must determine which encoding and orchestration
wrappers translate and which adapter code still needs a refinement argument.
Record any unextracted adapter logic in the trusted base. A controller theorem
conditional on those adapters is useful, but does not by itself certify the
complete concrete protocol implementation.

Cryptographic assumptions must be named hypotheses or boundary contracts with
owners, not new Lean axioms that assert the desired security conclusion. An
ideal-cryptography theorem is distinct from a computational reduction. The
initial implementation claim will explicitly assume reviewed library security,
entropy and nonce discipline; it will not claim proofs of Ed25519, AES-GCM,
TLS or TPM silicon. SHA-256 binding uses collision resistance, not mathematical
injectivity. Random nonces have collision probabilities and per-key usage
limits; they are not guaranteed unique merely because a CSPRNG produced them.

## 6. Implementation boundaries that support the proofs

Keep the protocol controller deterministic and extractable. It receives
authenticated evidence and opaque credential references, and emits closed
intents. Put token encoding/crypto, TLS, credential acquisition/storage and
provider HTTP in narrow adapters. Use the same controller from the conformance
runner and service; a separate Lean mirror does not verify the Rust program.

The Rust service will own credential custody and the egress connection. Raw
credential access belongs to a private custody/executor module, with no general
secret-to-string callback available to application code. Secret types must not
implement public formatting or serialization. Only trusted adapters construct
authenticated-peer, opened-token and authorized-dispatch evidence; public
deserialization cannot manufacture them. Type privacy supports the boundary but
is not itself the information-flow proof. Libraries that copy secrets remain
inside the declared trusted boundary; zeroization cannot prove all copies gone.

The authenticated request must stay associated with its connection, issued
surrogate, credential authority, provider and exact operation throughout
substitution. Redirects, alternate origins, proxy environment, raw HTTP
forwarding, token-in-query export, debug output and unwrapped child tokens must
not create another credentialed route. Credential acquisition/refresh responses
and browser redirects also remain on the trusted side; an error path must not
return a token endpoint's raw body.

Initially expose only one existing named operation against a synthetic provider.
Prove its request and response contract through the entire path before adding
more operations. The operation may have broad useful authority; a numerical
request quota is not part of this milestone's value proposition.

## 7. Current source and evidence gaps

| Existing boundary | Evidence to reuse | Work before claiming protocol correctness |
| --- | --- | --- |
| Pure issue/present model | Python contracts/vectors plus extracted Rust issuance/opening and use/release proofs | Complete correspondence with the concrete service and authentic inputs |
| Token envelopes | Python/Rust exact outer fixture and bidirectional inner/outer crypto interoperability | Concrete encoding/crypto adapter refinement and nonce analysis |
| Authenticated connection | Actual Rust/Python TLS tests, opaque peer evidence and Rust provider path | Formal transport refinement and complete connection/request association |
| Acquisition and refresh | Python-compatible native encrypted vault, pinned HTTPS refresh, durable-before-send extracted controller, opaque leases through native dispatch, process-death/write-failure/concurrency tests | Native browser/callback/code-exchange acquisition; concrete storage/error/concurrent-service trace refinement |
| Substitution and result release | Original broker/egress tests plus Rust account-status-v1 custody, route tests and extracted typed-release noninterference | Review/extend the public disclosure contract, general provider mediation and whole-service confinement/refinement |
| Instance key custody | Rust TPM signer, fresh creation-evidence verifier under a trusted AK pin, actual isolated swtpm/TLS tests | Authenticate hardware AK provenance, EK activation, approved deployment/PCR/rollback policy and physical TPM validation |
| Native authority | Python-compatible durable Rust administration, assurance receipts, issuer/server/CA rotation, explicit prefix-checked recovery, protected file issuance, held-directory storage, extracted admission/trust-publication contracts and live native bridge leases | Complete storage/locking and concurrent-service history refinement; general policy and browser OAuth acquisition |

The Python executor currently returns successful provider JSON or text to the
broker, which places it in the result and checks literal credential reflection.
Guest presentation rules such as `json_fields` are not a server confidentiality
boundary. This remains an explicit gap for GARR-CONF-01 in the general Python
profile. The Rust account-status-v1 profile instead selects a typed public
projection explicitly; its conditional release theorem is described separately.
The original Python pure issue/present model alone does not include TLS,
signatures, encryption, provider substitution or secrets.

Revocation currently consults trusted registry/key state at request entry, while
broker grant liveness is rechecked at emission and credential-generation guards
have their own locking semantics. Before strengthening GARR-USE-01 to mean
current *at dispatch*, specify and prove the synchronization across these
boundaries. A stale authenticated snapshot is not current authority. Ordinary
restart, rollback, VM clone, CA change and issuer retirement require separate
trace cases; rollback resistance needs a trustworthy freshness anchor or an
explicit assumption excluding rollback.

The native authority bridge now holds a shared authority lease through dispatch;
participating administrative writers acquire its exclusive lease. Tests show
revocation drains already admitted provider requests and prevents later uses,
and waiting on a lease does not extend a token lifetime. Its current-peer and
ordered-publication controllers are extracted and checked, but the concrete
file-lock/filesystem implementation and concurrent service histories are not
yet refined in Lean. The independent-file bridge retains snapshot semantics.
TPM assurance receipts bind fresh verified evidence to installed certificates;
they are trusted host metadata, not proof of physical hardware or a workload.

### Next implementation sequence after native refresh custody

1. Finish normal Rust authorization-code acquisition. Keep PKCE verifier and
   pending state on the trusted host, bind a loopback listener before opening
   the browser, check the exact callback path/state/issuer/expiry and consume
   one pending authorization once. Exchange only with the approved token
   origin and install through the existing vault transaction. The ordinary
   service must exercise these rules; a JSON transition runner alone does
   not close acquisition. Add browser/callback substitution, duplicate-code,
   timeout and lost-response tests with synthetic endpoints.
2. Extend the Rust provider interpreter deliberately. Keep credential sources
   opaque, make request builders consume host-approved routes and typed
   arguments, and choose each operation's public-result disclosure contract.
   Prove destination/action confinement and release properties before adding
   a provider operation. Preserve the successful-action witness alongside
   attack rejections. This must not accidentally become an arbitrary HTTP
   proxy or unrestricted provider-body return path.
3. Connect the actual lease boundaries to a finite service-history theorem.
   Model enrollment/root/issuer changes and OAuth refresh/revoke together,
   including blocked dispatch, crashes and uncertain publication. State the
   exact trusted adapter postconditions and show that each emitted request
   has a current admitted identity and credential lease. Existing controller
   and symbolic histories are reusable, but are not that whole-service proof.
4. Validate a deployment's key-custody premise independently. Provision an AK
   trust origin, exercise the chosen physical TPM/VM isolation arrangement,
   and document who can reach its signing oracle or clone its state. Emulator
   signing/creation tests do not establish those deployment facts. An external
   security review must assess the disclosure contract and trusted base before
   any broader assurance claim.

## 8. Milestones and acceptance gates

| Stage | Concrete deliverable | Exit gate |
| --- | --- | --- |
| G0 profile and attacker model | Freeze this project's nested Garrett profile, observations, trust contracts and source-to-obligation map | Review the claim and its assumptions; mark every unproved boundary |
| G1 protocol model | Executable symbolic issue/present/substitute model, attacker deduction rules and success/rejection traces | Lean secrecy and correspondence statements with positive witnesses; no assumptions that restate the conclusion |
| G2 implementation connection | Independent extractable Rust controller, byte-exact token wrappers and protocol runner | Aeneas-derived refinement proofs, existing Python vectors plus crypto interoperability and new adversarial traces |
| G3 credential use | Minimal Rust service owns synthetic credentials, mTLS and a single reviewed provider operation | Successful action with no agent credential; public-sink and route proof/test coverage through real adapters |
| G4 instance binding | Chosen TPM/vTPM profile, enrollment evidence and signing-backed client | Verified key evidence, successful real TLS signing, failed stolen-token use from an independent instance |
| G5 composed assurance | Connect freshness, enrollment generations, custody, release and dispatch linearization | Named conditional protocol theorem and complete assumption/proof manifest for a pinned service build |

G1 and the G2 extraction spike should inform one another so that the formal model
fits the supported Rust subset. G3 is the point where the implementation can
demonstrate useful action and actual custody together. G4 supplies evidence for
the deployment-specific key-custody premise; the TPM and its implementation
remain trusted, and a software-key test supplies no hardware-custody evidence.
These stages are a multiweek campaign with review gates, not a calendar promise.

The first demo must exercise both success and attack paths:

- The enrolled client performs the operation; it receives the allowed result
  and the synthetic provider observes the right authentication field.
- A separate client steals the complete surrogate and public certificate,
  reaches the broker, and fails before credentialed provider I/O.
- Another legitimately enrolled certificate, spoofed peer fields, altered
  claims/ciphertext, stale epochs, retired issuers and mixed inner/outer tokens
  all fail at their stated boundaries.
- Attempts to redirect credentials, export an inner capability, reflect errors
  or release disallowed provider fields fail without another privileged route.
- Identity/credential revocation at each modeled blocking boundary has the
  precisely specified effect on subsequent dispatch.

Replay Python and Rust traces against the versioned contract. Keep the existing
full Rust-runner gates pending until their entire advertised surfaces pass.
Use synthetic secrets only. Extend proof mutations to remove peer binding,
swap subjects/credentials, skip signature or AEAD checks, substitute associated
data and route the credential to a public sink. The relevant unchanged proof or
adapter test must reject each mutation; a stale-artifact hash failure alone is
not adequate. Publish separate results for symbolic proofs, extracted Rust
proofs, crypto/transport integration, hardware validation and Python parity.
