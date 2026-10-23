"""Manim entrypoint for proof_release. Edit the PLAN in aivis/plans/proof_release.py.

Run: python -m aivis render proof_release --quality l --still
"""

from aivis.scene_base import DiagramScene
from aivis.plans.proof_release import PLAN


class ProofReleaseScene(DiagramScene):
    PLAN = PLAN
