"""Manim entrypoint for proof_constrained. Edit the PLAN in aivis/plans/proof_constrained.py.

Run: python -m aivis render proof_constrained --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.proof_constrained import PLAN


class ProofConstrainedScene(DiagramScene):
    PLAN = PLAN
