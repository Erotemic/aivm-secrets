"""Manim entrypoint for projection. Edit the PLAN in aivis/plans/projection.py.

For custom transitions, override construct and use Manim directly.
Run: python -m aivis render projection --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.projection import PLAN


class SelectiveDisclosureScene(DiagramScene):
    PLAN = PLAN
