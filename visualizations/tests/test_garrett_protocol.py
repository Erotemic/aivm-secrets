"""Pedagogical regression gates for the separate original-Garrett storyboard.

These check consistency of the authored depictions, not implementation
correctness or a whole-process security theorem.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

from aivis.catalog import VIS_ROOT, get_scene, load_catalog, validate_catalog
from aivis.diagram import layer_geometry
from aivis.svg_preview import render_svg

G = VIS_ROOT / 'storyboards' / 'garrett_protocol.toml'
NAMES = ['gp_programs','gp_keys','gp_issue','gp_packet','gp_request',
         'gp_replay','gp_replicas','gp_compromise']


def test_standalone_catalog_does_not_modify_existing_deck():
    original = [s.id for s in validate_catalog()]
    assert original[0] == 'legend'
    assert 'gp_programs' not in original
    assert [s.id for s in validate_catalog(G)] == NAMES
    assert load_catalog(G)[0]['name'] == 'garrett-protocol'


def test_garrett_original_protocol_not_stateful_aivs1():
    packet = get_scene('gp_packet', path=G).diagram()
    layers = [layer for layer, *_ in layer_geometry(packet.packages[0])]
    assert [l.kind for l in layers] == ['signed','plain','encrypted','private']
    assert [l.key for l in layers] == ['jwt','claims','enc','real_token']
    assert not any('aivs1' in l.title.lower() or 'aivs1' in l.note.lower() for l in layers)
    assert packet.visible_layer_depth('S', 0) == 0
    assert packet.visible_layer_depth('S', 3) == 3


def test_key_custody_and_compromise_are_explicit():
    keys = get_scene('gp_keys', path=G).diagram()
    initial = keys.state('initial')[2]
    holdings = {k.owner: ' '.join(k.items) for k in initial.knowledge}
    assert 'Kseal' in holdings['broker'] and 'Kseal' in holdings['proxy']
    assert 'skIssuer' in holdings['broker'] and 'pkIssuer' in holdings['proxy']
    assert 'skAgent' in holdings['agent'] and 'No Kseal' in holdings['agent']
    assert 'No credential database' in holdings['broker']
    assert 'No credential database' in holdings['proxy']
    request = get_scene('gp_request', path=G).diagram()
    assert request.beat_names().index('binding') < request.beat_names().index('decrypt')
    assert request.beat_names().index('decrypt') < request.beat_names().index('forward')
    replay = get_scene('gp_replay', path=G).diagram()
    assert 'before decrypting' in replay.state('deny')[2].caption
    attack = get_scene('gp_compromise', path=G).diagram()
    assert 'mTLS cannot prevent' in attack.state('compromise')[2].caption


def test_all_animation_beats_preview_as_valid_standalone_svg():
    for scene in validate_catalog(G):
        plan = scene.diagram()
        for beat in range(len(plan.beats)):
            drawing = render_svg(plan, beat=beat)
            root = ET.fromstring(drawing)
            assert root.attrib['width'] == '1440'
            assert plan.title in drawing


def test_cli_standalone_selection_and_isolated_build_root():
    env = os.environ.copy()
    env['AIVIS_STORYBOARD'] = 'garrett_protocol'
    proc = subprocess.run([sys.executable, '-m', 'aivis', 'list'],
                          cwd=VIS_ROOT, env=env, capture_output=True,text=True)
    assert proc.returncode == 0, proc.stderr
    ids = [line.split()[0] for line in proc.stdout.strip().splitlines()]
    assert ids == NAMES
    proc = subprocess.run([sys.executable, '-m', 'aivis', 'render', 'gp_packet', '--dry-run'],
                          cwd=VIS_ROOT, env=env, capture_output=True,text=True)
    assert proc.returncode == 0,proc.stderr
    assert str(VIS_ROOT / '.build' / 'garrett_protocol' / 'media') in proc.stdout
    assert 'GarrettProtocolPacketScene' in proc.stdout
