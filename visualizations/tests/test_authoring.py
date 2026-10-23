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

SCENES=['legend','boundary','garrett_enroll','garrett_issue','packaging',
        'garrett_present','garrett_stolen','gh_diff','dispatch','projection',
        'reflection','evidence','proof_map','proof_send','proof_release',
        'proof_two_worlds', 'proof_proxy', 'proof_write_gate']


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
    assert next(s for s in data['scenes'] if s['id']=='gh_diff')['editPlan']=='aivis/plans/gh_diff.py'
    assert next(s for s in data['scenes'] if s['id']=='gh_diff')['beats'][1]['packet']=='pr.diff {repo, pr}'
    assert len(next(s for s in data['scenes'] if s['id']=='gh_diff')['beats'][0]['knowledge'])==3
    assert 'client_alias.rs' in ' '.join(next(s for s in data['scenes'] if s['id']=='gh_diff')['optionalSources'])
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


def test_garrett_protocol_is_visible_before_github():
    order = [s.id for s in validate_catalog()]
    assert order.index('garrett_enroll') < order.index('garrett_issue')
    assert order.index('garrett_issue') < order.index('packaging')
    assert order.index('packaging') < order.index('garrett_present')
    assert order.index('garrett_stolen') < order.index('gh_diff')
    enrollment = get_scene('garrett_enroll').diagram()
    assert {'csr', 'approve', 'deliver'} <= set(enrollment.beat_names())
    assert 'private key' in ' '.join(enrollment.state('csr')[2].knowledge[0].items)
    issue = get_scene('garrett_issue').diagram()
    assert 'no GitHub bearer' in issue.state('deliver')[2].knowledge[2].items
    presentation = get_scene('garrett_present').diagram()
    assert {'peer', 'verify', 'unseal', 'authorize'} <= set(presentation.beat_names())
    stolen = get_scene('garrett_stolen').diagram()
    assert 'no inner unseal' in stolen.state('reject')[2].knowledge[1].items
    assert 'signing oracle' in stolen.footer


def test_party_icons_shared_by_svg_and_manim():
    from aivis.icons import embedded_icon, icon_art, icon_name
    from aivis.diagram import Node
    assert icon_name(Node('agent','Agent','Sandbox',(0,0),role='guest')) == 'sandbox'
    assert icon_name(Node('github','GitHub API','HTTPS',(0,0),role='provider')) == 'github'
    for name in ['sandbox', 'github', 'host', 'authority', 'certificate', 'audit', 'vault']:
        filled, elements = icon_art(name)
        assert isinstance(filled, bool) and elements
        assert 'transform=' in embedded_icon(name, x=10,y=10,size=22,color='#adeeaa')
    assert '<path ' in render_svg(get_scene('gh_diff').diagram())
    with pytest.raises(ValueError, match='unknown icon'):
        icon_art('nonexistent.svg')


def test_presentation_build_renders_only_changed_scenes(tmp_path,monkeypatch):
    from aivis import presentation
    destination=tmp_path/'presentation'
    monkeypatch.setattr(presentation,'PRESENTATION',destination)
    monkeypatch.setattr(presentation,'MANIFEST',destination/'manifest.json')
    revisions={}
    fingerprint=presentation.scene_fingerprint
    monkeypatch.setattr(presentation,'scene_fingerprint',
                        lambda info,**kw:fingerprint(info,**kw)+str(revisions.get(info.id,0)))
    calls=[]
    def render(scene_id):
        calls.append(scene_id)
        path=tmp_path/'renders'/f'{scene_id}.mp4'
        path.parent.mkdir(exist_ok=True)
        path.write_bytes((scene_id+' '+str(len(calls))).encode())
        return path
    output,changed=presentation.build_presentation(render_scene=render)
    assert list(changed)==SCENES
    assert output.is_file()
    assert all((destination/'videos'/f'{scene}.mp4').is_file() for scene in SCENES)
    assert 'videos/garrett_present.mp4' in output.read_text()
    calls.clear()
    output,changed=presentation.build_presentation(render_scene=render)
    assert changed==() and calls==[]
    revisions['garrett_enroll']=1
    output,changed=presentation.build_presentation(render_scene=render)
    assert changed==('garrett_enroll',) and calls==['garrett_enroll']
    calls.clear()
    output,changed=presentation.build_presentation(render_scene=render,theme='light')
    assert len(changed)==len(SCENES)
    assert calls==SCENES
    assert 'id="video"' in output.read_text()
    assert 'id="motion"' in output.read_text()


def test_presentation_failed_scene_does_not_commit_cache(tmp_path,monkeypatch):
    from aivis import presentation
    dest=tmp_path/'presentation'
    monkeypatch.setattr(presentation,'PRESENTATION',dest)
    monkeypatch.setattr(presentation,'MANIFEST',dest/'manifest.json')
    def abort(scene_id):
        raise RuntimeError('Manim failed')
    with pytest.raises(RuntimeError,match='Manim failed'):
        presentation.build_presentation(render_scene=abort)
    assert not (dest/'manifest.json').exists()
