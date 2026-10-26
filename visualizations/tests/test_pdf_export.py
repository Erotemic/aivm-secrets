"""Keep PDF contracts independent of whether the Manim extra is installed."""

import pytest

from aivis.catalog import load_catalog
from aivis.gallery import build_gallery
from aivis.pdf_export import build_pdfs


@pytest.fixture
def pdf_stack():
    pytest.importorskip('cairosvg')
    return pytest.importorskip('pypdf')


def test_vector_pdf_handout_and_scene_cache(tmp_path, pdf_stack):
    scenes = load_catalog()[1]
    result = build_pdfs(directory=tmp_path, scene='all', kind='handout')
    handout, summary_count = result['handout']
    assert summary_count == len(scenes)
    reader = pdf_stack.PdfReader(handout)
    assert len(reader.pages) == len(scenes)
    first = reader.pages[0]
    assert abs(float(first.mediabox.width / first.mediabox.height) - 16/9) < 0.001
    assert scenes[0].diagram().title in first.extract_text()
    assert b'/Font' in handout.read_bytes()  # selectable vector text, not a screenshot
    result = build_pdfs(directory=tmp_path, scene='packaging', kind='both')
    full, count = result['beats']
    assert count == len(next(s for s in scenes if s.id == 'packaging').diagram().beats)
    assert len(pdf_stack.PdfReader(full).pages) == count
    assert result['handout'][1] == 1
    cached = {p.name: p.stat().st_mtime_ns for p in (tmp_path / '.page-cache').glob('*.pdf')}
    again = build_pdfs(directory=tmp_path, scene='packaging', kind='both')
    assert again['beats'][1] == count
    assert {p.name: p.stat().st_mtime_ns for p in (tmp_path / '.page-cache').glob('*.pdf')} == cached


def test_individual_scene_and_light_theme(tmp_path, pdf_stack):
    result = build_pdfs(directory=tmp_path, scene='packaging', kind='beats', theme='light')
    path, count = result['beats']
    assert path.name == 'packaging-light.pdf'
    assert len(pdf_stack.PdfReader(path).pages) == count
    assert count > 1
    assert not (tmp_path / 'presentation-light.pdf').exists()
    with pytest.raises(ValueError, match='unknown scene'):
        build_pdfs(directory=tmp_path, scene='not-a-scene')


def test_pdf_links_and_first_frame_mode(tmp_path):
    html = build_gallery(tmp_path / 'presentation.html',
                         pdfs={'presentation': '../pdfs/presentation.pdf',
                               'handout': '../pdfs/handout.pdf'}).read_text()
    assert 'href="../pdfs/presentation.pdf"' in html
    assert 'href="../pdfs/handout.pdf"' in html
    assert 'let showMotion = false;' in html
    assert html.count('Full PDF') == 1
    assert 'href="&quot;' not in html
    # Source of the link is escaped, not interpreted as HTML.
    html = build_gallery(tmp_path / 'escape.html', pdfs={'presentation': '" onmouseover="alert(1)'}).read_text()
    assert 'href="&quot; onmouseover=&quot;alert(1)"' in html
