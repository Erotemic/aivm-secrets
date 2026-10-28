"""Shared geometry and human-readable key custody notation for Garrett's protocol.

Presentation models, not executable credential operations.  ``Kseal`` denotes
AES-256-GCM key bytes. ``sk`` and ``pk`` denote private/public keys.
"""
from aivis.diagram import Knowledge

L = (-4.68, -0.78)
M = (0.0, -0.78)
R = (4.68, -0.78)


def knowledge(left, mid, right, *, names=('left', 'middle', 'right')):
    return (
        Knowledge(names[0], L, tuple(left), 3.86, 2.66),
        Knowledge(names[1], M, tuple(mid), 3.86, 2.66),
        Knowledge(names[2], R, tuple(right), 3.86, 2.66),
    )
