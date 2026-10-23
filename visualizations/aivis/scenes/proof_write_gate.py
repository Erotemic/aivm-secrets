"""Manim entrypoint for proof_write_gate. Edit the PLAN in aivis/plans/proof_write_gate.py.

Run: python -m aivis render proof_write_gate --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.proof_write_gate import PLAN


class ProofWriteGateScene(DiagramScene):
    PLAN = PLAN
