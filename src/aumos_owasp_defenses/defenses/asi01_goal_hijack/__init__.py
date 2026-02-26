"""ASI-01: Goal and Task Hijacking defenses.

Public surface
--------------
``BoundaryDetector``
    Main class — scan text for instruction-data boundary violations.
``BoundaryAnalysis``
    Immutable result value object returned by ``BoundaryDetector.analyze()``.
``InjectionFinding``
    A single pattern match within a ``BoundaryAnalysis``.
``ThreatLevel``
    Ordinal severity enum.
``check_safe``
    Convenience function — returns ``bool`` for quick gate checks.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi01_goal_hijack.boundary_detector import (
    BoundaryAnalysis,
    BoundaryDetector,
    InjectionFinding,
    ThreatLevel,
    check_safe,
)

__all__ = [
    "BoundaryAnalysis",
    "BoundaryDetector",
    "InjectionFinding",
    "ThreatLevel",
    "check_safe",
]
