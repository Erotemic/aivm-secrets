"""Standalone Garrett blog protocol: replay."""
from aivis.scene_base import DiagramScene
from aivis.plans.garrett_protocol_replay import PLAN


class GarrettProtocolReplayScene(DiagramScene):
    PLAN = PLAN
