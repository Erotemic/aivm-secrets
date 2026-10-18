# Run from visualizations/. No Rust/Lean setup is required for authoring.
PYTHON ?= python
SCENE ?= gh_diff
BEAT ?= last
QUALITY ?= l

.PHONY: help list storyboard check preview gallery render still watch watch-preview watch-gallery deck test
help:
	@echo 'list                 scenes, status, editable plan files'
	@echo 'storyboard           narrated scene outline + source mapping'
	@echo 'preview              instant SVG using the same diagram plan as Manim'
	@echo 'gallery              self-contained HTML with scene/beat controls (no Manim)'
	@echo 'render               only one Manim scene at draft quality'
	@echo 'still                last-frame Manim render (faster than video)'
	@echo 'watch                rerender one scene after source changes'
	@echo 'watch-preview        redraw SVG after source changes (no Manim needed)'
	@echo 'watch-gallery        rebuild interactive HTML after edits (no Manim needed)'
	@echo 'deck                 render all scene clips individually'
	@echo 'test                 standalone authoring tests'
	@echo 'Usage: make preview SCENE=packaging BEAT=ciphertext'
	@echo '       make watch SCENE=gh_diff QUALITY=l'
list:
	$(PYTHON) -m aivis list
storyboard:
	$(PYTHON) -m aivis storyboard
check:
	$(PYTHON) -m aivis check
preview:
	$(PYTHON) -m aivis preview $(SCENE) --beat $(BEAT)
gallery:
	$(PYTHON) -m aivis gallery
watch-gallery:
	$(PYTHON) -m aivis watch all --mode gallery
render:
	$(PYTHON) -m aivis render $(SCENE) --quality $(QUALITY)
still:
	$(PYTHON) -m aivis render $(SCENE) --quality $(QUALITY) --still
watch:
	$(PYTHON) -m aivis watch $(SCENE) --mode render --quality $(QUALITY)
watch-preview:
	$(PYTHON) -m aivis watch $(SCENE) --mode preview --beat $(BEAT)
deck:
	$(PYTHON) -m aivis deck --quality $(QUALITY)
test:
	$(PYTHON) -m pytest -q
