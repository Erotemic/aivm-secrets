# Animating the credential flow

These scenes explain how a request and its data move among the agent, the host
broker and the GitHub provider. They are **not** a simulation of the running
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
      packaging.py                 # nested surrogate cross-section
      gh_diff.py                   # worked example: gh pr diff 13861
      dispatch.py                  # checks before sending
      projection.py                # raw vs selected response fields
      reflection.py                # credential-reflection rejection
      evidence.py                  # implemented / proved / still open
    scenes/                         # tiny Manim entrypoints, one per concept
    components/graphics.py         # reusable Manim artwork
    scene_base.py                  # progressive reveal / movement / snapshots
    svg_preview.py                 # same diagram without Manim
    gallery.py                     # local browser viewer
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
uv run python -m aivis deck --quality l
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
