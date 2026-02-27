"""Tests for ScenarioRunner."""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.scenarios.library import AttackCategory, ScenarioLibrary, ThreatScenario
from aumos_owasp_defenses.scenarios.scenario_runner import (
    ScenarioResult,
    ScenarioRunReport,
    ScenarioRunner,
)
from aumos_owasp_defenses.defenses_suite.detector import DetectionResult


def _always_detect(input_data: dict) -> DetectionResult:
    return DetectionResult(detected=True, category="TEST", confidence=0.9, evidence=["test"])


def _never_detect(input_data: dict) -> DetectionResult:
    return DetectionResult(detected=False, category="TEST", confidence=0.0)


class TestScenarioResult:
    def test_to_dict_structure(self) -> None:
        result = ScenarioResult(
            scenario_id="PI-001",
            scenario_name="Test Scenario",
            detected=True,
            detection_confidence=0.85,
            latency_ms=1.5,
        )
        d = result.to_dict()
        assert d["scenario_id"] == "PI-001"
        assert d["detected"] is True
        assert d["detection_confidence"] == 0.85


class TestScenarioRunReport:
    def test_detection_rate_zero_runs(self) -> None:
        report = ScenarioRunReport(category_filter="ASI-01", total_run=0)
        assert report.detection_rate == 0.0

    def test_detection_rate_all_detected(self) -> None:
        results = [
            ScenarioResult(scenario_id="PI-001", scenario_name="x", detected=True, detection_confidence=0.9),
            ScenarioResult(scenario_id="PI-002", scenario_name="y", detected=True, detection_confidence=0.8),
        ]
        report = ScenarioRunReport(
            category_filter="ASI-01",
            results=results,
            total_run=2,
            detected_count=2,
            not_detected_count=0,
        )
        assert report.detection_rate == 1.0

    def test_average_confidence_empty(self) -> None:
        report = ScenarioRunReport(category_filter="all")
        assert report.average_confidence == 0.0

    def test_to_dict_structure(self) -> None:
        report = ScenarioRunReport(
            category_filter="ASI-02",
            total_run=3,
            detected_count=2,
            not_detected_count=1,
        )
        d = report.to_dict()
        assert d["total_run"] == 3
        assert d["detected_count"] == 2
        assert "detection_rate" in d


class TestScenarioRunner:
    def setup_method(self) -> None:
        self.library = ScenarioLibrary()

    def test_run_scenario_always_detect(self) -> None:
        runner = ScenarioRunner(detection_fn=_always_detect)
        scenario = self.library.get_by_id("PI-001")
        assert scenario is not None
        result = runner.run_scenario(scenario)
        assert isinstance(result, ScenarioResult)
        assert result.detected is True

    def test_run_scenario_never_detect(self) -> None:
        runner = ScenarioRunner(detection_fn=_never_detect)
        scenario = self.library.get_by_id("PI-001")
        assert scenario is not None
        result = runner.run_scenario(scenario)
        assert result.detected is False

    def test_run_scenario_records_latency(self) -> None:
        runner = ScenarioRunner(detection_fn=_always_detect)
        scenario = self.library.get_by_id("PI-001")
        assert scenario is not None
        result = runner.run_scenario(scenario)
        assert result.latency_ms >= 0.0

    def test_run_category_asi_01(self) -> None:
        runner = ScenarioRunner(detection_fn=_never_detect)
        report = runner.run_category("ASI-01", self.library)
        assert isinstance(report, ScenarioRunReport)
        assert report.total_run >= 5
        assert report.category_filter == "ASI-01"

    def test_run_category_counts_correctly(self) -> None:
        runner = ScenarioRunner(detection_fn=_always_detect)
        report = runner.run_category("ASI-02", self.library)
        assert report.detected_count == report.total_run
        assert report.not_detected_count == 0

    def test_run_all_runs_all_scenarios(self) -> None:
        runner = ScenarioRunner(detection_fn=_never_detect)
        report = runner.run_all(self.library)
        assert report.total_run == self.library.total_count
        assert report.category_filter == "all"

    def test_run_by_severity_critical(self) -> None:
        runner = ScenarioRunner(detection_fn=_always_detect)
        report = runner.run_by_severity("critical", self.library)
        assert report.total_run >= 1
        assert "critical" in report.category_filter

    def test_run_category_report_has_results(self) -> None:
        runner = ScenarioRunner(detection_fn=_always_detect)
        report = runner.run_category("ASI-01", self.library)
        assert len(report.results) == report.total_run

    def test_detection_rate_is_in_range(self) -> None:
        runner = ScenarioRunner(detection_fn=_never_detect)
        report = runner.run_all(self.library)
        assert 0.0 <= report.detection_rate <= 1.0
