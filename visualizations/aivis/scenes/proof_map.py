"""Manim entrypoint for proof_map. Edit the PLAN in aivis/plans/proof_map.py.

Run: python -m aivis render proof_map --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.proof_map import PLAN


class ProofMapScene(DiagramScene):
    PLAN = PLAN
