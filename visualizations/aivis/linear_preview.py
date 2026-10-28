"""One-click-per-beat SVG presentation, without a Manim installation.

Use this to review the same storyboard and order in seconds; ``make all``
replaces the stills with animated Manim Slides in a separate HTML file.
There are deliberately no selection or video controls on the presentation.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from aivis.catalog import load_catalog
from aivis.svg_preview import render_svg


def build_linear_preview(target: Path, *, theme: str = 'dark') -> Path:
    if theme not in {'dark', 'light'}:
        raise ValueError('theme must be dark or light')
    deck, scenes = load_catalog()
    slides = []
    for scene in scenes:
        plan = scene.diagram()
        for index, beat in enumerate(plan.beats):
            svg = render_svg(plan, beat=index, theme=theme).encode('utf-8')
            slides.append({
                'scene': scene.id,
                'beat': beat.key,
                'alt': f'{plan.title} - {beat.caption}',
                'image': 'data:image/svg+xml;base64,' + base64.b64encode(svg).decode('ascii'),
            })
    payload = json.dumps({'title': deck['title'], 'slides': slides}, ensure_ascii=True)
    payload = payload.replace('<', '\\u003c')
    bg = '#0b1422' if theme == 'dark' else '#f7f9fc'
    template = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
html, body {margin:0; width:100%; height:100%; overflow:hidden; background:__BG__;}
body {display:grid; place-items:center; cursor:pointer;}
img {display:block; width:100vw; height:100vh; object-fit:contain; user-select:none;
     -webkit-user-drag:none;}
</style>
</head>
<body>
<img id="slide" alt="Protocol diagram" draggable="false">
<script type="application/json" id="slide-data">__PAYLOAD__</script>
<script>
const slides = JSON.parse(document.getElementById('slide-data').textContent).slides;
const image = document.getElementById('slide');
let index = 0;
function show(next) {
  index = Math.max(0, Math.min(slides.length - 1, next));
  image.src = slides[index].image;
  image.alt = slides[index].alt;
}
document.addEventListener('click', event => {
  if (event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey) show(index + 1);
});
document.addEventListener('keydown', event => {
  if (['ArrowRight','PageDown','Enter',' '].includes(event.key)) {
    event.preventDefault(); show(index + 1);
  } else if (['ArrowLeft','PageUp','Backspace'].includes(event.key)) {
    event.preventDefault(); show(index - 1);
  } else if (event.key === 'Home') {
    event.preventDefault(); show(0);
  } else if (event.key === 'End') {
    event.preventDefault(); show(slides.length - 1);
  } else if (event.key.toLowerCase() === 'f') {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen?.();
    else document.exitFullscreen?.();
  }
});
show(0);
</script>
</body>
</html>
'''
    # Encode the title as ordinary HTML text rather than render it through JS.
    from html import escape
    html = (template.replace('__TITLE__', escape(deck['title']))
            .replace('__BG__', bg).replace('__PAYLOAD__', payload))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding='utf-8')
    return target
