"""Fast checks of the *authoring* contract (no Manim/Rust/Lean required)."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import re
from xml.etree import ElementTree as ET

import pytest

from aivis.__main__ import main, render_command
from aivis.catalog import VIS_ROOT, REPO_ROOT, get_scene, load_catalog, validate_catalog
from aivis.diagram import Layer, layer_geometry, validate
from aivis.gallery import build_gallery
from aivis.palette import palette
from aivis.svg_preview import CANVAS_H, CANVAS_W, render_svg, write_preview

SCENES=['legend','boundary','packaging','gh_diff','dispatch','projection','reflection','evidence']


def test_catalog_is_ordered_for_protocol_walkthrough():
    scenes=validate_catalog()
    assert [s.id for s in scenes]==SCENES
    assert all((VIS_ROOT/s.file).is_file() for s in scenes)
    assert all((VIS_ROOT/(s.plan.replace('.','/')+'.py')).is_file() for s in scenes)
    assert all(s.claim and s.narration and s.sources for s in scenes)
    assert all(s.status!='whole-service-verified' for s in scenes)


def test_scene_entrypoints_small_and_isolated():
    for scene in validate_catalog():
        content=(VIS_ROOT/scene.file).read_text()
        assert len(content.splitlines()) <= 25
        assert 'from aivis.plans.' in content
        assert scene.diagram().key==scene.id


def test_beat_order_and_revelation_is_cumulative():
    for scene in validate_catalog():
        d=scene.diagram()
        nprev,eprev=set(),set()
        for index,beat in enumerate(d.beats):
            nodes,edges,active,number=d.state(index)
            nkeys={n.key for n in nodes}; ekeys={e.key for e in edges}
            assert nkeys>=nprev and ekeys>=eprev
            assert active is beat and number==index
            nprev,eprev=nkeys,ekeys
        assert nprev==set(d.node_map())
        assert eprev==set(d.link_map())


def test_nested_token_structure_is_not_plaintext_for_guest():
    d=get_scene('packaging').diagram()
    layers=[layer for layer,*_ in layer_geometry(d.package_map()['token'])]
    assert [layer.kind for layer in layers]==['signed','encrypted','sealed','private']
    assert [layer.key for layer in layers]==['surrogate','outer_cipher','inner_cap','bearer']
    assert d.visible_layer_depth('token',0)==0
    assert d.visible_layer_depth('token',1)==1
    assert d.visible_layer_depth('token',2)==2
    assert d.visible_layer_depth('token',3)==3
    assert d.visible_layer_depth('token',4)==3
    assert d.visible_packages(0)==list(d.packages)
    assert 'x-ray' in d.kicker.lower()


def test_knowledge_is_replaced_not_accumulated():
    d=get_scene('boundary').diagram()
    initial=d.state('start')[2].knowledge
    sent=d.state('send')[2].knowledge
    assert 'credential' in ' '.join(initial[1].items)
    assert 'bearer' in ' '.join(sent[2].items)
    assert not any('bearer token' in item and not item.startswith('no ')
                   for item in sent[0].items)
    assert len(initial)==len(sent)==3
    assert {k.owner for k in initial}=={'guest','host','provider'}


def test_tauceti_gh_walkthrough_scoped_and_statused():
    d=get_scene('gh_diff').diagram()
    assert d.beat_names()==('command','translate','check','preflight','audit','provider','raw','release')
    assert '13861' in d.title
    assert 'TauCetiProject/TauCeti' in d.kicker
    assert d.state('translate')[2].packet_label=='pr.diff {repo, pr}'
    assert d.state('provider')[2].packet_label=='GET approved .diff'
    assert d.state('release')[2].knowledge[0].items[-1]=='not the bearer'
    assert any(b.status=='idealized' for b in d.beats)
    assert any(b.status=='implemented' for b in d.beats)
    assert 'not unrestricted' in d.footer.lower() or 'not arbitrary' in d.footer.lower()
    for beat in d.beats:
        assert {k.owner for k in beat.knowledge}=={'agent','broker','github'}


def test_package_and_knowledge_validation_is_fail_closed():
    plan=get_scene('packaging').diagram()
    with pytest.raises(ValueError,match='unknown package layer'):
        validate(replace(plan, beats=(replace(plan.beats[0],layer_focus='made_up'),)+plan.beats[1:]))
    bad=replace(plan.packages[0], outer=Layer('surrogate','wrong','visible','private'))
    with pytest.raises(ValueError,match='unknown package layer'):
        validate(replace(plan, packages=(bad,)))
    plan=get_scene('gh_diff').diagram()
    with pytest.raises(ValueError,match='duplicate knowledge holders'):
        validate(replace(plan,beats=(replace(plan.beats[0],
            knowledge=(plan.beats[0].knowledge[0],plan.beats[0].knowledge[0])),)+plan.beats[1:]))
    with pytest.raises(ValueError,match='moving packet text without route'):
        validate(replace(plan,beats=(replace(plan.beats[0], packet_label='secret'),)+plan.beats[1:]))


def test_link_cannot_point_to_missing_node_or_box_center():
    d=get_scene('boundary').diagram()
    route=d.links[0]
    with pytest.raises(ValueError,match='missing endpoint'):
        validate(replace(d,links=(replace(route,destination='ghost'),)+d.links[1:]))
    with pytest.raises(ValueError,match='misses'):
        validate(replace(d,links=(replace(route,path=((0,0),(1,1))),)+d.links[1:]))


@pytest.mark.parametrize('theme',['dark','light'])
def test_every_scene_and_beat_has_valid_svg(theme,tmp_path):
    for scene in validate_catalog():
        diagram=scene.diagram()
        for j,step in enumerate(diagram.beats):
            xml=render_svg(diagram,beat=j,theme=theme)
            root=ET.fromstring(xml)
            assert root.attrib['width']==str(CANVAS_W)
            assert root.attrib['height']==str(CANVAS_H)
            assert diagram.title in xml
            assert step.key.upper() in xml
            output=tmp_path/f'{scene.id}-{j}.svg'
            write_preview(diagram,output,beat=j,theme=theme)
            assert output.read_text()==xml


def test_svg_nested_layers_reveal_one_at_a_time():
    diagram=get_scene('packaging').diagram()
    for i,key in enumerate(['surrogate','outer_cipher','inner_cap','bearer']):
        svg=render_svg(diagram,beat=i)
        assert 'Provider credential' in svg if i>=3 else 'Provider credential' not in svg
        assert key in [layer.key for layer,*_ in layer_geometry(diagram.packages[0])]


def test_svg_text_is_escaped():
    d=get_scene('legend').diagram()
    xml=render_svg(replace(d,title='<surrogate &amp; token>'))
    ET.fromstring(xml)
    assert '&lt;surrogate &amp;amp; token&gt;' in xml


def test_semantic_palette_is_complete():
    assert set(palette('dark'))==set(palette('light'))
    assert palette('dark')['secret']!=palette('dark')['broker']
    with pytest.raises(ValueError): palette('ultraviolet')


def test_cli_render_is_safe_and_per_scene(capsys):
    cmd,env=render_command('gh_diff',still=True,quality='l',theme='light',speed=1.4)
    assert cmd[:3][-2:]==['-m','manim']
    assert cmd[-2:]==['aivis/scenes/gh_diff.py','GitHubDiffWalkthroughScene']
    assert '-s' in cmd and '-ql' in cmd
    assert env['AIVIS_THEME']=='light'
    assert env['AIVIS_SPEED']=='1.4'
    assert main(['list'])==0
    assert 'packaging' in capsys.readouterr().out
    assert main(['storyboard'])==0
    assert '1. legend' in capsys.readouterr().out
    assert main(['render','gh_diff','--dry-run','--still'])==0
    assert 'GitHubDiffWalkthroughScene' in capsys.readouterr().out
    with pytest.raises(ValueError,match='unknown scene'):
        render_command('rm -rf /')
    for value in ('-1','2,1','x','1,2,3'):
        with pytest.raises(ValueError,match='animation'):
            render_command('gh_diff',animation=value)


def test_gallery_contains_knowledge_and_source_references(tmp_path):
    html=build_gallery(tmp_path/'index.html').read_text()
    match=re.search(r'<script type="application/json" id="story-data">(.*?)</script>',html,re.S)
    assert match is not None
    data=json.loads(match.group(1))
    assert [s['id'] for s in data['scenes']]==SCENES
    assert data['scenes'][3]['editPlan']=='aivis/plans/gh_diff.py'
    assert data['scenes'][3]['beats'][1]['packet']=='pr.diff {repo, pr}'
    assert len(data['scenes'][3]['beats'][0]['knowledge'])==3
    assert 'client_alias.rs' in ' '.join(data['scenes'][3]['optionalSources'])
    assert 'id="inventory"' in html
    assert 'id="beat"' in html
    assert '<script src=' not in html
    assert all(beat['image'].startswith('data:image/svg+xml;base64,')
               for scene in data['scenes'] for beat in scene['beats'])


def test_gallery_javascript_is_syntax_valid(tmp_path):
    import shutil,subprocess
    if not shutil.which('node'):
        pytest.skip('Node.js is optional')
    html=build_gallery(tmp_path/'index.html').read_text()
    js=re.findall(r'<script(?: [^>]*)?>(.*?)</script>',html,re.S)[-1]
    file=tmp_path/'storyboard.js';file.write_text(js)
    outcome=subprocess.run(['node','--check',str(file)],capture_output=True,text=True)
    assert outcome.returncode==0,outcome.stderr


def test_proof_refs_exist_but_are_not_whole_service_claims():
    for scene in validate_catalog():
        for anchor in scene.proof_anchors:
            theorem=anchor.rsplit('.',1)[-1]
            assert any(f'theorem {theorem}' in (REPO_ROOT/path).read_text()
                       for path in scene.sources if path.endswith('.lean'))
    assert 'W6' in get_scene('evidence').diagram().footer or 'whole service' in get_scene('evidence').diagram().footer
    assert 'reveal information' in get_scene('reflection').claim.lower()
