# Animating the Garrett protocol and a brokered `gh` request

These scenes explain how a client receives a certificate, how the host issues
a signed encrypted surrogate, how the TLS bridge opens it only for the bound
client, and how the resulting restricted `gh` request reaches GitHub.
They show what information each party holds at every step. They are **not** a simulation of the running
service. The `gh` walkthrough is an idealized read-only scenario; every beat
records whether the illustrated part exists in code, depends on the deployment,
or is not yet proved.

The same small Python plans drive the Manim animations and the fast SVG/HTML
preview. You can edit a single beat without rebuilding the whole presentation.

## Files to edit

```text
visualizations/
  storyboards/overview.toml        # order, narration, sources, scope
  aivis/
    diagram.py                      # Node / Link / Layer / Package / Knowledge / Beat
    plans/
      legend.py                    # readable / signed / encrypted / host-only
      boundary.py                  # who knows what at each step
      garrett_enroll.py            # CSR, operator approval, client certificate
      garrett_issue.py             # host-only credential -> signed surrogate
      packaging.py                 # nested surrogate cross-section
      garrett_present.py           # mutual TLS, binding and host-side opening
      garrett_stolen.py            # why a copied surrogate fails under cert B
      gh_diff.py                   # worked example: gh pr diff 13861
      dispatch.py                  # checks before sending
      projection.py                # raw vs selected response fields
      reflection.py                # credential-reflection rejection
      evidence.py                  # implemented / proved / still open
    scenes/                         # tiny Manim entrypoints, one per concept
    assets/icons/*.svg             # editable local role icons, GitHub mark
    components/graphics.py         # reusable Manim artwork and SVG icons
    scene_base.py                  # progressive reveal / movement / snapshots
    svg_preview.py                 # same diagram and icons without Manim
    presentation.py                # cache changed scene videos for HTML
    gallery.py                     # browser viewer: video or stepped diagrams
    pdf_export.py                  # vector PDF: all beats or final-beat handout
  tests/test_authoring.py
  .build/                           # generated previews and videos; not committed
```

`plans/*.py` is the primary editing surface. Each plan contains ordinary
`Node`, `Link`, `Knowledge`, `Package`, `Layer`, and `Beat` definitions:

- **`Node` / `Link`**: parties and the arrows crossing their boundaries.
- **`Knowledge`**: a complete snapshot of one party's current information.
  Copying a value does not erase the sender's copy. Change a `Beat.knowledge`
  tuple to show exactly what the parties have *after that step*.
- **`Beat.packet` / `Beat.packet_label`**: the route and label of the object
  traveling across it. It animates in Manim and is labeled in the SVG still.
- **`Package` / `Layer`**: concentric signed, encrypted and nested layers. The
  inside of an encrypted layer is shown only as an **X-ray explanation**—the
  agent does not get plaintext merely because the viewer can see the diagram.
- **`Beat.layer_focus`**: gradually unwraps a nested package. To add another
  layer, edit `aivis/plans/packaging.py`, not the SVG/Manim rendering code.
- **`Beat.status`**: `implemented`, `idealized`, `assumed`, `open`, or
  `explainer`. Labels refer to that step, not to the whole service.

Editing the geometry changes *both* renderers. If you want independent Manim
motion beyond the shared base, override `construct()` in a small scene file.

## Quick start: HTML, PDF, and videos

Run commands from `visualizations/`. They use the project's **own** `.venv`
through `uv run`; an active unrelated `python`/`uvpy` environment does not
matter. The `.python-version` file selects Python 3.13 (uv can install it if
needed). No Rust/Lean toolchain is involved.

```bash
cd ~/code/aivm-secrets/visualizations
make view                    # diagrams + printable PDFs, no Manim
xdg-open .build/storyboard.html
```

This produces a standalone, self-contained HTML storyboard and two
**selectable-text, vector** 16:9 PDFs:

| Output | Meaning |
| --- | --- |
| `.build/storyboard.html` | Interactive scene / beat chooser, notes, inventories; open locally |
| `.build/pdfs/presentation.pdf` | All storyboard beats in order (102 pages in the 2026-10-26 storyboard) |
| `.build/pdfs/handout.pdf` | Last beat of each scene, one page per scene (19 pages in the 2026-10-26 storyboard) |

These PDFs are made **directly from the SVG scene plans**, not screenshots
from video; the text, arrows, packages, and linework stay vector graphics.
They illustrate the same storyboards as Manim but are not frame grabs of
Manim's animated motion. They do not need Manim, FFmpeg, or a running server.
For a smaller PDF or a light-background print version:

```bash
make pdf SCENE=packaging KIND=beats
make pdf THEME=light
make handout
```

A single-scene PDF is `.build/pdfs/packaging.pdf`; the light-themed full
outputs are `presentation-light.pdf` and `handout-light.pdf`. PDFs are
cached per beat, so unchanged visuals need not be converted again. Use
`make pdf` for both outputs without regenerating the HTML.

For animations and an HTML viewer with playable clips, run:

```bash
make all QUALITY=l
xdg-open .build/presentation/index.html
```

`make all` **installs the required Python extras through uv** and renders
only changed Manim scenes at draft quality. It includes the same two PDFs,
with links in the browser presentation, and stores individual MP4 clips in
`.build/presentation/videos/`. Open `index.html` locally; it needs its
neighboring `videos/` directory. The viewer starts on the stepped diagram,
so it is useful immediately even before you click **Play animation**.

To refresh an animation after editing:

```bash
make watch-all QUALITY=l
```

The watcher tracks Python plans/scene code, storyboard TOML and local icon
SVGs. It invalidates only affected Manim clips; a narration-only change
refreshes the HTML without rerendering videos. Changes to diagram plans
also flow into the rebuilt PDFs. To force all Manim clips to rerender:

```bash
uv run --extra manim --extra pdf python -m aivis all --quality l --force
```

If Manim's system libraries are missing on Ubuntu, install them before
`make all`:

```bash
sudo apt install ffmpeg pkg-config libcairo2-dev libpango1.0-dev
```

Run `make setup` to pre-install Manim, PDF, and test extras, or `make setup-pdf`
for PDFs only. `make view` / `make pdf` do not require those system Manim
dependencies. Python dependency versions resolve from `pyproject.toml` /
`uv.lock`; the first run may update the lockfile for newly added PDF extras.

## Garrett scene sequence

The sequence before `gh_diff` has five parts:

1. **Enrollment:** a client/VM holds its private key, the authority approves
   enrollment, and the host records a certificate and epoch.
2. **Issuance:** the host wraps the credential in an inner `aivs1` capability,
   encrypts it in the outer envelope, binds it to that certificate, and signs
   the surrogate.
3. **Packaging:** an X-ray of public signed claims, AES-GCM ciphertext,
   opaque inner capability and host-protected credential bytes.
4. **Presentation:** client-authenticated TLS supplies the actual peer
   identity; the host verifies and opens the surrogate, then separately checks
   the inner grant before using the provider token.
5. **Stolen token:** cert B cannot use a surrogate bound to cert A without
   being able to authenticate as A.

Then the `gh pr diff 13861` example begins. This is an **idealized composition**
of the native Garrett and constrained GitHub paths, not evidence that every
step of a composite deployment has been proved. Existing native code covers
specific components; the complete runtime I/O and isolation contracts remain
separate work. Do not animate untrusted guest access to the inner plaintext as
if it were a real capability.

The icons are local vector assets under `aivis/assets/icons/`. The sandbox
icon identifies the untrusted guest environment, not a VM isolation proof.
The GitHub silhouette identifies the API endpoint; its reuse and attribution
notes are in the icon README. `Node(icon='github')` selects a specific symbol;
otherwise roles supply defaults such as `sandbox`, `host`, and `vault`.

## What the proofs say

The proof-focused scenes after `evidence` explain the scope of the
production-instance Lean theorems. Each scene uses `proof_anchors` to link
back to specific theorem names (a catalog test fails if a named theorem
is removed):

- `proof_map`: which code each stage of one read runs, extracted-and-proved
  (green) or native-and-trusted (amber), with assumption IDs from
  `docs/planning/aivm-secrets-assumption-roadmap.md`.
- `proof_send`: how a provider attempt's bytes are pinned to the request
  encoded for the captured route, and what native trust remains.
- `proof_release`: what a successful read frame is byte-for-byte, and the
  17 fixed denial lines.
- `proof_write_gate`: when a write may run: the extracted approval decision and
  the write gate in front of the production controller (OUT-4).
- `proof_proxy`: where the optional credential-substitution proxy writes the
  credential (one verified line), what it drops, and why it is not confinement.
- `proof_two_worlds`: noninterference as two provider worlds an adaptive
  guest cannot tell apart, with the declassifications (selected JSON, row
  count, status class) shown explicitly.

## Editing and targeted builds

The plans are designed for incremental authoring. Choose a beat, edit its
nodes/links/caption in `aivis/plans/`, then preview it without rendering
all scenes:

```bash
cd ~/code/aivm-secrets/visualizations
make list
make check
make preview SCENE=packaging BEAT=ciphertext
make gallery
make render SCENE=gh_diff QUALITY=l
make still SCENE=packaging QUALITY=l
make test
```

`make gallery` writes `.build/storyboard.html`; its controls show the current
knowledge for each party, moving packet labels, narration, scene sources and
edit paths. It works without video renders. Use `make watch-gallery` for
continuous HTML refreshes, or `make watch-preview SCENE=packaging` for an SVG
beat. Refresh your browser after changes. The watchers ignore generated
`.build` artifacts.

Manim output stays under `.build/media/`, while `make all` copies the finished
clips into the presentation. Direct CLI usage is also available:

```bash
uv run --extra manim --extra pdf python -m aivis render gh_diff --quality l
uv run --extra pdf python -m aivis pdf proof_write_gate --kind beats
uv run python -m aivis render gh_diff --dry-run
```

The `--animation N,M` Manim option renders a subset of zero-based `play`
indices; `--beat name` instead previews a deterministic SVG checkpoint.
Test the package without Manim using `make test` (the PDF tests use the PDF
extra). No scene preview by itself certifies a security property: use the
source and proof anchors to inspect each claim.

## Scope of the example

The worked example uses the repository's TauCeti PR 13861 fixture and a
read-only `pr.diff` operation. A narrow W2 native `gh` translator exists when
that overlay has been applied; this **does not** mean the guest runs arbitrary
`gh` commands with broad host credentials. The guest holds a surrogate and an
authenticated identity; the broker constructs the allowed HTTPS request and
selects the return value. This walkthrough simplifies retries, concurrency,
errors and audit persistence.

The surrogate diagram follows the actual signed/AES-GCM outer envelope and the
host-encrypted inner `aivs1` capability. It is an explanatory cross-section,
not a byte-accurate JWT encoder or a claim that issuer keys, TLS or storage are
formally verified. The source paths for every scene live in
`storyboards/overview.toml`; optional source references are permitted when
another overlay has not yet been applied.

The extracted Rust controller proofs cover selected authorization and
projection decisions. **W6 still needs to connect them to every concrete I/O
path; W8 covers the deployment's VM/channel isolation assumptions.** The
animations never stand in for those obligations.

## Separate deck: Garrett's **original stateless protocol**

The main `overview.toml` mixes the AIVM host's stateful `aivs1` capability
and policy architecture with some Garrett-inspired concepts. It must **not**
be presented as a literal depiction of the protocol in Matthew Garrett's
[July 2, 2026 article](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/).

A new, independently selected storyboard in
`storyboards/garrett_protocol.toml` explains **the original stateless surrogate
protocol** using eight animated scenes. The same `Diagram` source drives
Manim, vector SVG and the HTML storyboard. Its program and key inventories
show which processes hold `Kseal`, `skIssuer`, `pkIssuer`, and `skAgent`;
its X-ray distinguishes a *signed, readable JWT* from the `enc` field that
contains the AES-GCM ciphertext. It does **not** insert an inner `aivs1`
capability or credential database that Garrett's proposal does not require.

```bash
cd visualizations
make garrett-check
make garrett-gallery         # no Manim; open .build/garrett_protocol/storyboard.html
make garrett-pdf             # optional pdf extra; prints every animation beat
make garrett-render SCENE=gp_keys QUALITY=l
make garrett-render SCENE=gp_packet QUALITY=l
make garrett-all QUALITY=l # all eight Manim clips + independent HTML presentation
```

The standalone outputs live under `.build/garrett_protocol/` instead of
`.build/presentation/`, so rendering this deck cannot overwrite the existing
presentation. To preview a specific animation checkpoint without Manim:

```bash
AIVIS_STORYBOARD=garrett_protocol uv run python -m aivis preview gp_request --beat binding
```

The storyboard order is: `gp_programs`, `gp_keys`, `gp_issue`, `gp_packet`,
`gp_request`, `gp_replay`, `gp_replicas`, `gp_compromise`.

This is an **architecture explanation**, not a formal verification result.
`garrett-stateless-v1` is the concrete implementation used for the diagram's
algorithm and claim names (Ed25519, AES-256-GCM, JWT `enc`, `cnf`). Garrett's
blog does not prescribe those particular encodings. The login example uses
OAuth, but credential acquisition is separable from the sealing mechanism.

The broker transiently receives the original provider token and could decrypt
compatible surrogates because it has `Kseal`; the proxy likewise has `Kseal`.
Neither needs a token database. mTLS prevents a stolen surrogate from being
used through an honest proxy without the bound client private key; it does
**not** prevent a fully compromised proxy with `Kseal` from decrypting a
captured surrogate. No general provider-response sanitization guarantee is
implied by Garrett's original proposal.
