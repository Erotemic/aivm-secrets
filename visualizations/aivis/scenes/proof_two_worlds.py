"""Manim entrypoint for proof_two_worlds. Edit the PLAN in aivis/plans/proof_two_worlds.py.

Run: python -m aivis render proof_two_worlds --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.proof_two_worlds import PLAN


class ProofTwoWorldsScene(DiagramScene):
    PLAN = PLAN
