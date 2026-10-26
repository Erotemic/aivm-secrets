# All recipes run through the project-managed uv environment, never the active
# shell's Python (which may be an unrelated uvpy / system environment).
UV      ?= uv
SCENE   ?= all
BEAT    ?= last
QUALITY ?= l
THEME   ?= dark
KIND    ?= both

RUN       := $(UV) run
RUN_PDF   := $(UV) run --extra pdf
RUN_MANIM := $(UV) run --extra manim --extra pdf
RUN_TEST  := $(UV) run --extra pdf --extra test

.DEFAULT_GOAL := help
.PHONY: help setup setup-pdf list storyboard check preview gallery view pdf handout \
        render still watch watch-preview watch-gallery deck all watch-all test clean

help:
	@echo 'Run from visualizations/ (uses uv-managed .venv automatically)'
	@echo '  make view                  fast interactive HTML + two vector PDFs (no Manim)'
	@echo '  make all                   cached Manim videos + HTML + full PDF + handout PDF'
	@echo '  make pdf                   vector PDFs, all beats + last-beat handout (no Manim)'
	@echo '  make pdf SCENE=packaging KIND=beats'
	@echo '  make handout               one page per scene, no Manim'
	@echo '  make gallery               standalone interactive HTML, no Manim'
	@echo '  make preview SCENE=packaging BEAT=last'
	@echo '  make render SCENE=gh_diff QUALITY=l'
	@echo '  make still SCENE=gh_diff   Manim still image'
	@echo '  make list | storyboard | check | test'
	@echo '  make watch-all             watch edits and refresh videos + PDFs + HTML'
	@echo '  make setup                 install Manim, PDF and tests in .venv'
	@echo '  make setup-pdf             install PDF tools only'
	@echo '  make clean                 remove generated .build/ files'
	@echo 'PDFs: .build/pdfs/presentation.pdf and .build/pdfs/handout.pdf'
	@echo 'HTML: .build/presentation/index.html (make all), .build/storyboard.html (make view)'
	@echo 'Variables: SCENE=<id>|all QUALITY=l|m|h|p THEME=dark|light KIND=both|beats|handout'

setup:
	$(UV) sync --extra manim --extra pdf --extra test
setup-pdf:
	$(UV) sync --extra pdf
list:
	$(RUN) python -m aivis list
storyboard:
	$(RUN) python -m aivis storyboard
check:
	$(RUN) python -m aivis check
preview:
	$(RUN) python -m aivis preview $(SCENE) --beat $(BEAT) --theme $(THEME)
gallery:
	$(RUN) python -m aivis gallery --theme $(THEME)
view:
	$(RUN_PDF) python -m aivis pdf --theme $(THEME)
	$(RUN_PDF) python -m aivis gallery --theme $(THEME)
pdf:
	$(RUN_PDF) python -m aivis pdf $(SCENE) --kind $(KIND) --theme $(THEME)
handout:
	$(RUN_PDF) python -m aivis pdf --kind handout --theme $(THEME)
render:
	$(RUN_MANIM) python -m aivis render $(SCENE) --quality $(QUALITY) --theme $(THEME)
still:
	$(RUN_MANIM) python -m aivis render $(SCENE) --quality $(QUALITY) --theme $(THEME) --still
watch:
	$(RUN_MANIM) python -m aivis watch $(SCENE) --mode render --quality $(QUALITY) --theme $(THEME)
watch-preview:
	$(RUN) python -m aivis watch $(SCENE) --mode preview --beat $(BEAT) --theme $(THEME)
watch-gallery:
	$(RUN) python -m aivis watch all --mode gallery --theme $(THEME)
deck:
	$(RUN_MANIM) python -m aivis deck --quality $(QUALITY) --theme $(THEME)
all:
	$(RUN_MANIM) python -m aivis all --quality $(QUALITY) --theme $(THEME)
watch-all:
	$(RUN_MANIM) python -m aivis watch all --mode all --quality $(QUALITY) --theme $(THEME)
test:
	$(RUN_TEST) python -m pytest -q
clean:
	rm -rf .build
