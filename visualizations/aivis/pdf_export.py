"""Vector PDF decks built directly from the authored SVG storyboard plans.

These exports are independent of Manim, FFmpeg, and video frames.  A full deck
has a page for every beat; the handout contains the final beat of each scene.
Both follow the catalog order and preserve 16:9 vector linework and text.
"""
from __future__ import annotations

from io import BytesIO
import hashlib
import os
from pathlib import Path
from typing import Iterable

from aivis.catalog import VIS_ROOT, SceneInfo, build_root, get_scene, load_catalog
from aivis.svg_preview import render_svg

PDF_DIR = build_root() / 'pdfs'


def _pdf_dependencies():
    # Keep the planning, gallery and Manim authoring imports lightweight.
    try:
        import cairosvg
        from pypdf import PdfReader, PdfWriter
    except ImportError as error:
        raise RuntimeError(
            'PDF export requires the pdf extra: from visualizations/ run '
            '`uv run --extra pdf python -m aivis pdf` (or `make pdf`).'
        ) from error
    return cairosvg, PdfReader, PdfWriter


def write_pdf(pages: Iterable[tuple[SceneInfo, int]], target: Path,
              *, theme: str = 'dark') -> tuple[Path, int]:
    """Write a 16:9 vector PDF atomically from (scene, zero-based beat) pairs."""
    if theme not in ('dark', 'light'):
        raise ValueError('theme must be dark/light')
    cairosvg, PdfReader, PdfWriter = _pdf_dependencies()
    # Convert first, then merge. Interleaving font-intensive SVG conversion
    # with repeated pypdf object-cloning can cause excessive memory churn.
    page_files: list[Path] = []
    cache = target.parent / '.page-cache'
    for scene, beat_index in pages:
        svg = render_svg(scene.diagram(), beat=beat_index, theme=theme).encode('utf-8')
        signature = hashlib.sha256(b'aivis-svg-pdf-v1\0' +
                                   cairosvg.__version__.encode('ascii') + b'\0' + svg).hexdigest()
        page_file = cache / f'{signature}.pdf'
        if not page_file.is_file():
            cache.mkdir(parents=True, exist_ok=True)
            temporary_page = cache / f'{signature}.pdf.part'
            try:
                cairosvg.svg2pdf(bytestring=svg, write_to=str(temporary_page))
                os.replace(temporary_page, page_file)
            finally:
                temporary_page.unlink(missing_ok=True)
        page_files.append(page_file)
    if not page_files:
        raise ValueError('cannot export an empty PDF')
    writer = PdfWriter()
    for page_file in page_files:
        writer.append(PdfReader(BytesIO(page_file.read_bytes())))
    writer.add_metadata({
        '/Title': 'aivm-secrets | where information goes',
        '/Subject': 'Authored protocol storyboard; explanation, not a complete runtime proof',
        '/Creator': 'aivis (vector SVG storyboard)',
    })
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + '.part')
    try:
        with temporary.open('wb') as file:
            writer.write(file)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return target, len(page_files)


def build_pdfs(*, scene: str = 'all', kind: str = 'both', theme: str = 'dark',
               directory: Path | None = None) -> dict[str, tuple[Path, int]]:
    """Export either the full walkthrough or a single scene.

    ``beats`` means every beat, ``handout`` means the last beat of each scene,
    and ``both`` creates both named files.  Single-scene exports use that
    scene's name, so they cannot overwrite the full-presentation outputs.
    """
    if kind not in ('beats', 'handout', 'both'):
        raise ValueError('kind must be beats/handout/both')
    if theme not in ('dark', 'light'):
        raise ValueError('theme must be dark/light')
    if scene == 'all':
        _, scenes = load_catalog()
    else:
        scenes = (get_scene(scene),)  # validate before creating any output
    output_dir = directory or PDF_DIR
    suffix = '' if theme == 'dark' else '-light'
    result = {}
    prefix = 'presentation' if scene == 'all' else scene
    if kind in ('beats', 'both'):
        pages = ((item, i) for item in scenes for i, _ in enumerate(item.diagram().beats))
        result['beats'] = write_pdf(pages, output_dir / f'{prefix}{suffix}.pdf', theme=theme)
    if kind in ('handout', 'both'):
        pages = ((item, len(item.diagram().beats)-1) for item in scenes)
        name = 'handout' if scene == 'all' else f'{scene}-handout'
        result['handout'] = write_pdf(pages, output_dir / f'{name}{suffix}.pdf', theme=theme)
    return result
