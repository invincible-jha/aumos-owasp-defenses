"""ASI-10: Rogue / Emergent Agent Behaviors defenses.

Public surface
--------------
``BaselineProfiler``
    Records behavioral observations and builds statistical baselines.
``AgentBaseline``
    Snapshot of a full behavioral baseline for one agent.
``MetricBaseline``
    Per-metric baseline snapshot.
``DriftDetector``
    Detects behavioral drift from a baseline using z-score analysis.
``DriftCheckResult``
    Aggregate result of ``DriftDetector.check()``.
``MetricDriftFinding``
    Per-metric drift finding within a ``DriftCheckResult``.
``DriftSeverity``
    Enum: NONE, WATCH, ALERT, CRITICAL, INSUFFICIENT_DATA.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi10_rogue_agents.baseline_profiler import (
    AgentBaseline,
    BaselineProfiler,
    MetricBaseline,
)
from aumos_owasp_defenses.defenses.asi10_rogue_agents.drift_detector import (
    DriftCheckResult,
    DriftDetector,
    DriftSeverity,
    MetricDriftFinding,
)

__all__ = [
    "AgentBaseline",
    "BaselineProfiler",
    "DriftCheckResult",
    "DriftDetector",
    "DriftSeverity",
    "MetricBaseline",
    "MetricDriftFinding",
]
