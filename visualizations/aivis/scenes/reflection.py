"""Manim entrypoint for reflection. Edit the PLAN in aivis/plans/reflection.py.

For custom transitions, override construct and use Manim directly.
Run: python -m aivis render reflection --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.reflection import PLAN


class ReflectionOracleScene(DiagramScene):
    PLAN = PLAN
