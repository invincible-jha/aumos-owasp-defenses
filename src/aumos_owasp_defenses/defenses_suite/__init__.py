"""Defense suite — per-category defense+detector pair with detect/defend/simulate."""
from __future__ import annotations

from aumos_owasp_defenses.defenses_suite.detector import (
    BaseDetector,
    DetectionResult,
)
from aumos_owasp_defenses.defenses_suite.defense_suite import (
    DefenseSuite,
    DefenseSuiteResult,
    SuiteCategory,
)
from aumos_owasp_defenses.defenses_suite.simulator import (
    AttackSimulator,
    SimulationScenario,
)

__all__ = [
    "BaseDetector",
    "DetectionResult",
    "DefenseSuite",
    "DefenseSuiteResult",
    "SuiteCategory",
    "AttackSimulator",
    "SimulationScenario",
]
