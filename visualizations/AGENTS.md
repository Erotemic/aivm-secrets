# Visualization authoring

Explain **who has what, what moves, and what is wrapped**. Prefer factual,
short captions to security-claim marketing. The main storyboard is the
credential-flow walkthrough, not a theorem audit slideshow.

Editing guidance:

- Text/order/scope/source references: `storyboards/overview.toml`.
- Party positions, holdings, packets, nesting and animation beats:
  `aivis/plans/<scene>.py`.
- Generic shapes and animation mechanics: `aivis/components/graphics.py`,
  `aivis/scene_base.py`, and `aivis/svg_preview.py`. Keep all three derived from
  one `Diagram`; don't fork hard-coded SVG/Manim layouts.
- Actual custom Manim movement: edit one `aivis/scenes/<scene>.py` entrypoint.
  Don't add a monolithic deck script or numbered `final_v2` scene variants.

Keep the visualization package optional and independent of Rust/Lean. Use
`python -m aivis check`, `python -m aivis gallery` and
`python -m pytest -q tests/test_authoring.py` for fast feedback.

The data cross-section is an X-ray view; nested plaintext labels are not
visible to the guest. Signing is not encryption. A proxy-mediated provider
request is not unrestricted GitHub CLI access. Do not call VM isolation or
W6 adapter correspondence proved. Status labels must say what was implemented,
what is an idealized step, and what is an environmental assumption.

Treat scene notes and source paths as a reviewable account of the code, not
something the animation itself can certify. Use one Manim scene render for
motion checks when dependencies are available. Do not add theorem axiom dumps
or invoke the Lean suite during routine visual revisions.

## Garrett information-flow scenes and combined HTML rendering

The storyboard now includes `garrett_enroll`, `garrett_issue`,
`garrett_present`, and `garrett_stolen` before `gh_diff`. Prefer readable
actor/packet labels to proof jargon. Private signing keys and host provider
credentials never travel to the untrusted guest; nested encrypted layers
are an X-ray for the audience only. Do not confuse a signed claim with
encryption, or possession of a copied surrogate with possession of its bound
client signing key. For precise source links, edit `storyboards/overview.toml`.

The authoring fast path is `python -m aivis gallery`. For a video + HTML
presentation use `make all PYTHON=.venv/bin/python QUALITY=l`, then open
`.build/presentation/index.html`. `make watch-all` rebuilds changed scenes
and HTML when authored Python/TOML/SVG changes. Both Manim and the SVG
renderer use the icons in `aivis/assets/icons/`; do not duplicate artwork.
All build output belongs under `.build/`, not source control.

An HTML presentation contains normal `.mp4` files alongside `index.html`:
keep the whole `.build/presentation/` directory together when sharing it.
The ability to animate a protocol is not a formal correctness claim.

## Build and publishing

- Use `make view` for HTML plus vector PDF outputs without Manim; use `make all`
  for the incremental video presentation and PDFs. Do not call the active shell
  Python from Makefile recipes; invoke the project through `uv run` with the
  correct extras.
- `aivis/pdf_export.py` uses the existing SVG/diagram plans as its page
  source. Keep PDF and SVG authoring unified; avoid duplicating slide text
  in a separate PDF generator or rasterizing videos. PDF handouts take the
  final beat of each scene.
- Check vector PDF readability by rendering representative pages and confirming
  page count and selectable text. Never let a storyboard's `implemented`
  label imply whole-service proof coverage.
