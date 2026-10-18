"""Manim entrypoint for dispatch. Edit the PLAN in aivis/plans/dispatch.py.

For custom transitions, override construct and use Manim directly.
Run: python -m aivis render dispatch --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.dispatch import PLAN


class AuthorizedDispatchScene(DiagramScene):
    PLAN = PLAN
