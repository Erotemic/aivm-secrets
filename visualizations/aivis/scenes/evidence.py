"""Manim entrypoint for evidence. Edit the PLAN in aivis/plans/evidence.py.

For custom transitions, override construct and use Manim directly.
Run: python -m aivis render evidence --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.evidence import PLAN


class EvidenceChainScene(DiagramScene):
    PLAN = PLAN
