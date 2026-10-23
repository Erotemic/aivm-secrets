"""Manim entrypoint for proof_proxy. Edit the PLAN in aivis/plans/proof_proxy.py.

Run: python -m aivis render proof_proxy --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.proof_proxy import PLAN


class ProofProxyScene(DiagramScene):
    PLAN = PLAN
