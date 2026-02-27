"""ScenarioRunner — run a defense against a threat scenario and check detection.

The runner takes a ThreatScenario and a detection function, exercises the
defense with a structurally representative benign test input, and records
whether the defense correctly identifies the pattern.

Example
-------
::

    from aumos_owasp_defenses.scenarios.scenario_runner import ScenarioRunner
    from aumos_owasp_defenses.scenarios.library import ScenarioLibrary
    from aumos_owasp_defenses.defenses_suite.defense_suite import DefenseSuite, SuiteCategory

    library = ScenarioLibrary()
    suite = DefenseSuite.for_category(SuiteCategory.GOAL_HIJACKING)
    runner = ScenarioRunner(detection_fn=suite.detect)
    report = runner.run_category("ASI-01", library)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from aumos_owasp_defenses.scenarios.library import ScenarioLibrary, ThreatScenario


@dataclass
class ScenarioResult:
    """Result of running a single scenario through a defense.

    Attributes
    ----------
    scenario_id:
        The ID of the scenario that was run.
    scenario_name:
        Human-readable scenario name.
    detected:
        Whether the defense detected a threat.
    detection_confidence:
        Confidence score from the detector.
    evidence:
        Evidence strings from the detection.
    latency_ms:
        Wall-clock time for the detection call.
    """

    scenario_id: str
    scenario_name: str
    detected: bool
    detection_confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "detected": self.detected,
            "detection_confidence": self.detection_confidence,
            "evidence": self.evidence,
            "latency_ms": self.latency_ms,
        }


@dataclass
class ScenarioRunReport:
    """Aggregate report for running multiple scenarios through a defense.

    Attributes
    ----------
    category_filter:
        OWASP ASI category filter used for this run (or ``"all"``).
    results:
        Per-scenario results.
    total_run:
        Total number of scenarios run.
    detected_count:
        Number of scenarios where a threat was detected.
    not_detected_count:
        Number of scenarios where no threat was detected.
    """

    category_filter: str
    results: list[ScenarioResult] = field(default_factory=list)
    total_run: int = 0
    detected_count: int = 0
    not_detected_count: int = 0

    @property
    def detection_rate(self) -> float:
        """Fraction of scenarios where a threat was detected (0.0–1.0)."""
        if self.total_run == 0:
            return 0.0
        return self.detected_count / self.total_run

    @property
    def average_confidence(self) -> float:
        """Average detection confidence across all results."""
        if not self.results:
            return 0.0
        return sum(r.detection_confidence for r in self.results) / len(self.results)

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "category_filter": self.category_filter,
            "total_run": self.total_run,
            "detected_count": self.detected_count,
            "not_detected_count": self.not_detected_count,
            "detection_rate": self.detection_rate,
            "average_confidence": self.average_confidence,
            "results": [r.to_dict() for r in self.results],
        }


def _build_test_input_for_scenario(scenario: ThreatScenario) -> dict[str, object]:
    """Build a structurally representative test input for a scenario.

    Uses the scenario's detection_pattern to construct a minimal test input
    that exercises the relevant detection code path. All inputs are benign
    and contain no real attack payloads.
    """
    # Map scenario categories to input structures
    owasp_to_input: dict[str, dict[str, object]] = {
        "ASI-01": {"text": "What is the weather today?"},
        "ASI-02": {"tool": "search", "params": {"query": "test query"}},
        "ASI-03": {"agent_id": "agent-1", "role": "reader", "action": "read"},
        "ASI-04": {"plugin_id": "my-plugin", "source": "https://registry.example.com"},
        "ASI-05": {"code": "print('hello')", "sandbox": True},
        "ASI-06": {"memory_key": "user_preference", "content": "Use formal tone."},
        "ASI-07": {"sender_id": "agent-2", "message": "Please complete this subtask."},
        "ASI-08": {"service": "api-service", "status": "healthy", "latency_ms": 100},
        "ASI-09": {"source": "external", "claim": "I am a trusted system.", "trust_level": 0},
        "ASI-10": {"action_count": 5, "token_usage": 1000, "error_rate": 0.01},
    }
    return owasp_to_input.get(scenario.owasp_asi, {"input": "benign test input"})


# Type alias for detection functions
DetectionFn = Callable[[dict[str, object]], object]


class ScenarioRunner:
    """Run named threat scenarios through a defense detection function.

    Parameters
    ----------
    detection_fn:
        A callable that accepts a dict of input data and returns an object
        with ``detected`` (bool), ``confidence`` (float), and
        ``evidence`` (list[str]) attributes. Compatible with BaseDetector.detect().

    Example
    -------
    ::

        from aumos_owasp_defenses.defenses_suite.defense_suite import DefenseSuite, SuiteCategory

        suite = DefenseSuite.for_category(SuiteCategory.GOAL_HIJACKING)
        runner = ScenarioRunner(detection_fn=suite.detect)
        report = runner.run_category("ASI-01", library)
        print(report.detection_rate)
    """

    def __init__(self, detection_fn: DetectionFn) -> None:
        self._detection_fn = detection_fn

    def run_scenario(self, scenario: ThreatScenario) -> ScenarioResult:
        """Run a single scenario through the detection function.

        Parameters
        ----------
        scenario:
            The scenario to exercise.

        Returns
        -------
        ScenarioResult
            Detection outcome for this scenario.
        """
        test_input = _build_test_input_for_scenario(scenario)
        start_ns = time.monotonic_ns()
        detection = self._detection_fn(test_input)
        latency_ms = (time.monotonic_ns() - start_ns) / 1_000_000

        return ScenarioResult(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            detected=bool(getattr(detection, "detected", False)),
            detection_confidence=float(getattr(detection, "confidence", 0.0)),
            evidence=list(getattr(detection, "evidence", [])),
            latency_ms=latency_ms,
        )

    def run_category(
        self,
        owasp_asi: str,
        library: ScenarioLibrary,
    ) -> ScenarioRunReport:
        """Run all scenarios for a given OWASP ASI category.

        Parameters
        ----------
        owasp_asi:
            OWASP ASI category identifier (e.g. ``"ASI-01"``).
        library:
            ScenarioLibrary to fetch scenarios from.

        Returns
        -------
        ScenarioRunReport
            Aggregate report for all scenarios in the category.
        """
        scenarios = library.get_by_owasp_asi(owasp_asi)
        return self._run_scenarios(scenarios, category_filter=owasp_asi)

    def run_all(self, library: ScenarioLibrary) -> ScenarioRunReport:
        """Run all scenarios in the library through the detection function.

        Parameters
        ----------
        library:
            ScenarioLibrary to fetch all scenarios from.

        Returns
        -------
        ScenarioRunReport
            Aggregate report for all scenarios.
        """
        return self._run_scenarios(library.list_all(), category_filter="all")

    def run_by_severity(
        self,
        severity: str,
        library: ScenarioLibrary,
    ) -> ScenarioRunReport:
        """Run all scenarios at a given severity level.

        Parameters
        ----------
        severity:
            One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
        library:
            ScenarioLibrary to fetch scenarios from.
        """
        scenarios = library.get_by_severity(severity)
        return self._run_scenarios(scenarios, category_filter=f"severity:{severity}")

    def _run_scenarios(
        self,
        scenarios: list[ThreatScenario],
        *,
        category_filter: str,
    ) -> ScenarioRunReport:
        """Internal helper to run a list of scenarios and build a report."""
        results: list[ScenarioResult] = []
        detected = 0
        not_detected = 0

        for scenario in scenarios:
            result = self.run_scenario(scenario)
            results.append(result)
            if result.detected:
                detected += 1
            else:
                not_detected += 1

        return ScenarioRunReport(
            category_filter=category_filter,
            results=results,
            total_run=len(results),
            detected_count=detected,
            not_detected_count=not_detected,
        )
