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
