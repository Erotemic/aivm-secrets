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

## One command for the Manim + HTML presentation

From the visualization directory, install Manim once, then run `make all`:

```bash
cd ~/code/aivm-secrets/visualizations
uv sync --extra manim --extra test
make all PYTHON=.venv/bin/python QUALITY=l
xdg-open .build/presentation/index.html
```

`make all` renders only **changed** scenes at draft quality, copies their MP4s
into `.build/presentation/videos/`, and regenerates the HTML viewer. The HTML
lets you switch between the **rendered video** and the **editable beat-by-beat
SVG** for each scene, and lists the corresponding plan and source files.
The HTML and videos are kept together as a folder, not embedded into a huge
single file. Open the local `index.html`; no web server is needed.

To rebuild on edits, in a separate terminal:

```bash
cd ~/code/aivm-secrets/visualizations
make watch-all PYTHON=.venv/bin/python QUALITY=l
```

The watcher tracks changes to scene/plan Python files, storyboard TOML and
local icon SVGs. It calls the same incremental builder. Changing just
`aivis/plans/garrett_present.py` rerenders only the `garrett_present` clip;
changing shared drawing code or an icon rerenders every clip; changing the
storyboard narration refreshes the HTML without rerendering any videos.
Refresh the local browser after changes. To rerender all scenes regardless of
cache, run `python -m aivis all --quality l --force` using your Manim Python.
The generated `.build/` folder should not be added to git.

Use `make gallery` instead if you only need the instant SVG storyboard and do
not want to install Manim. The video builder requires Manim Community and
its system dependencies (Cairo/Pango/FFmpeg); it does not touch Rust or Lean.

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

Four scenes after `evidence` explain the production-instance Lean theorems,
each linked by `proof_anchors` to the exact theorem names (the catalog test
fails if a named theorem disappears):

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

## Instant feedback (no Manim installation)

From the visualization directory:

```bash
cd ~/code/aivm-secrets/visualizations
python -m aivis list
python -m aivis check
python -m aivis preview packaging --beat ciphertext
python -m aivis preview gh_diff --beat release
python -m aivis gallery
xdg-open .build/storyboard.html
```

`gallery` writes a **self-contained HTML file** with scene/beat controls,
current knowledge for each party, labels of moving objects, narration and edit
paths. No server runs in the background. You can leave this running in another
terminal while editing the plans:

```bash
cd ~/code/aivm-secrets/visualizations
python -m aivis watch all --mode gallery
```

Refresh the browser after each change. The watcher only reads authored source
files; it does not scan its own generated `.build` directory.

## Actual Manim video

In an independent visualization environment (not the Rust/Lean runtime):

```bash
cd ~/code/aivm-secrets/visualizations
uv sync --extra manim --extra test
uv run python -m aivis render gh_diff --quality l
uv run python -m aivis render packaging --quality l --still
uv run python -m aivis render boundary --quality l
uv run python -m aivis all --quality l
```

On Ubuntu, Manim Community may need system Cairo/Pango and FFmpeg packages.
The plans and previews themselves have no Manim, NumPy, or LaTeX dependency.
Manim output goes under `.build/media/`, and one scene is rendered at a time.

For targeted revision, pass `--animation N,M` to Manim for its zero-based
play-call indices, or use `--beat name` for a deterministic SVG checkpoint.
`python -m aivis render gh_diff --dry-run` prints the command without running
Manim. Use `python -m pytest -q tests/test_authoring.py` to check the plans.

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
