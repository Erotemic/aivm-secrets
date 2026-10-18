"""Manim entrypoint for boundary. Edit the PLAN in aivis/plans/boundary.py.

For custom transitions, override construct and use Manim directly.
Run: python -m aivis render boundary --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.boundary import PLAN


class TrustBoundaryScene(DiagramScene):
    PLAN = PLAN
