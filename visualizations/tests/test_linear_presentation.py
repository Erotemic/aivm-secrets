"""The primary presentation has no scene selector or manually played clips."""
from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from aivis.catalog import load_catalog
from aivis.linear_preview import build_linear_preview
from aivis.presentation import (convert_command, enable_click_to_advance,
                                present_command)


def test_one_click_per_storyboard_beat_without_controls(tmp_path):
    html = build_linear_preview(tmp_path / 'preview.html').read_text()
    match = re.search(r'<script type="application/json" id="slide-data">(.*?)</script>',
                      html, re.S)
    assert match is not None
    slides = json.loads(match.group(1))['slides']
    scenes = load_catalog()[1]
    expected = [(s.id, beat.key) for s in scenes for beat in s.diagram().beats]
    assert [(slide['scene'], slide['beat']) for slide in slides] == expected
    assert len(slides) == len(expected)
    assert all(slide['image'].startswith('data:image/svg+xml;base64,') for slide in slides)
    assert '<video ' not in html
    assert '<select ' not in html
    assert '<button ' not in html
    assert 'show(index + 1)' in html
    assert 'show(index - 1)' in html


def test_light_preview_theme(tmp_path):
    html = build_linear_preview(tmp_path / 'preview-light.html', theme='light').read_text()
    assert 'background:#f7f9fc' in html
    with pytest.raises(ValueError):
        build_linear_preview(tmp_path / 'broken.html', theme='violet')


def test_manim_slides_converter_is_linear_and_unadorned(tmp_path):
    scenes = load_catalog()[1]
    target = tmp_path / 'index.html'
    command = convert_command(target)
    assert command[1:4] == ['-m', 'manim_slides', 'convert']
    assert command[-(len(scenes) + 1):-1] == [s.class_name for s in scenes]
    assert command[-1] == str(target)
    assert '-ccontrols=false' in command
    assert '-cnavigation_mode=linear' in command
    assert '-coverview=false' in command
    assert '-cjump_to_slide=false' in command
    assert '-ccontrols_tutorial=false' in command
    assert '-cslide_number=false' in command
    assert '--one-file' not in command
    assert '--one-file' in convert_command(tmp_path / 'standalone.html', one_file=True)
    native = present_command()
    assert native[1:4] == ['-m', 'manim_slides', 'present']
    assert native[-len(scenes):] == [s.class_name for s in scenes]


def test_click_to_advance_injection_is_idempotent_and_excludes_ui(tmp_path):
    target = tmp_path / 'index.html'
    target.write_text('<!doctype html><html><body><div>slides</div></body></html>')
    enable_click_to_advance(target)
    enable_click_to_advance(target)
    html = target.read_text()
    assert html.count('data-aivis-click-to-advance') == 1
    assert 'Reveal.next()' in html
    assert "event.target.closest('a, button, input, select, textarea, [contenteditable]')" in html
    assert '<select' not in html
    invalid = tmp_path / 'invalid.html'
    invalid.write_text('<html>bad output</html>')
    with pytest.raises(RuntimeError, match='Expected HTML body'):
        enable_click_to_advance(invalid)


def test_inline_javascript_is_syntax_valid(tmp_path):
    if not shutil.which('node'):
        pytest.skip('Node.js is optional')
    preview = build_linear_preview(tmp_path / 'preview.html').read_text()
    script = re.findall(r'<script(?: [^>]*)?>(.*?)</script>', preview, re.S)[-1]
    file = tmp_path / 'linear.js'
    file.write_text(script)
    result = subprocess.run(['node', '--check', str(file)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    target = tmp_path / 'index.html'
    target.write_text('<body></body>')
    enable_click_to_advance(target)
    script = re.findall(r'<script(?: [^>]*)?>(.*?)</script>', target.read_text(), re.S)[-1]
    file.write_text(script)
    result = subprocess.run(['node', '--check', str(file)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_manim_slide_constructor_normalizes_string_output_folder(monkeypatch, tmp_path):
    """Exercise the real DiagramScene constructor without installing Manim.

    manim-slides BaseSlide saves output under ``self._output_folder / 'files'``.
    A str sneaks in via AIVIS_SLIDES_DIR and fails *after* animations render.
    """
    import importlib.util
    from pathlib import Path
    import sys
    from types import ModuleType

    from aivis.catalog import VIS_ROOT

    fake_manim = ModuleType('manim')
    for name in ('Circumscribe', 'Create', 'FadeIn', 'FadeOut', 'MoveAlongPath',
                 'RoundedRectangle', 'Text', 'VGroup', 'DOWN', 'UP'):
        setattr(fake_manim, name, object())
    fake_slides = ModuleType('manim_slides')

    class FakeSlide:
        def __init__(self, *args, output_folder, **kwargs):
            self._output_folder = output_folder

    fake_slides.Slide = FakeSlide
    fake_graphics = ModuleType('aivis.components.graphics')
    for name in ('edge_group', 'knowledge_card', 'link_path', 'node_card',
                 'package_group', 'region_box', 'text_label', 'traveling_label', 'xy'):
        setattr(fake_graphics, name, object())
    monkeypatch.setitem(sys.modules, 'manim', fake_manim)
    monkeypatch.setitem(sys.modules, 'manim_slides', fake_slides)
    monkeypatch.setitem(sys.modules, 'aivis.components.graphics', fake_graphics)

    # Load the actual class source in isolation so tests do not require native
    # Manim dependencies and do not pollute the normal aivis.scene_base import.
    path = VIS_ROOT / 'aivis/scene_base.py'
    spec = importlib.util.spec_from_file_location('aivis._test_scene_base', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    monkeypatch.delenv('AIVIS_SLIDES_DIR', raising=False)
    default = module.DiagramScene()._output_folder
    assert isinstance(default, Path)
    assert default == VIS_ROOT / '.build/slides'

    monkeypatch.setenv('AIVIS_SLIDES_DIR', str(tmp_path / 'from-env'))
    configured = module.DiagramScene()._output_folder
    assert isinstance(configured, Path)
    assert configured / 'files' == tmp_path / 'from-env/files'

    explicit = module.DiagramScene(output_folder=str(tmp_path / 'explicit'))._output_folder
    assert isinstance(explicit, Path)
    assert explicit == tmp_path / 'explicit'
