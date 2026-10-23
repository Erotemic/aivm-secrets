"""Manim entrypoint for proof_send. Edit the PLAN in aivis/plans/proof_send.py.

Run: python -m aivis render proof_send --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.proof_send import PLAN


class ProofSendScene(DiagramScene):
    PLAN = PLAN
