"""Tests for DefenseSuite."""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.defenses_suite.defense_suite import (
    DefenseSuite,
    DefenseSuiteResult,
    SuiteCategory,
)
from aumos_owasp_defenses.defenses_suite.detector import BaseDetector, DetectionResult
from aumos_owasp_defenses.defenses_suite.simulator import SimulationScenario


class AlwaysSafeDetector(BaseDetector):
    """Test detector that never triggers."""
    category = "ASI-TEST"

    def detect(self, input_data: dict) -> DetectionResult:
        return DetectionResult(detected=False, category=self.category, confidence=0.0)


class AlwaysThreatDetector(BaseDetector):
    """Test detector that always triggers."""
    category = "ASI-TEST"

    def detect(self, input_data: dict) -> DetectionResult:
        return DetectionResult(
            detected=True,
            category=self.category,
            confidence=0.99,
            evidence=["Always threat"],
        )


class TestDetectionResult:
    def test_to_dict_structure(self) -> None:
        result = DetectionResult(
            detected=True,
            category="ASI-01",
            confidence=0.8,
            evidence=["Pattern found"],
        )
        d = result.to_dict()
        assert d["detected"] is True
        assert d["category"] == "ASI-01"
        assert d["confidence"] == 0.8
        assert "Pattern found" in d["evidence"]


class TestDefenseSuiteForCategory:
    def test_create_for_goal_hijacking(self) -> None:
        suite = DefenseSuite.for_category(SuiteCategory.GOAL_HIJACKING)
        assert suite.category == "ASI-01"

    def test_create_for_tool_misuse(self) -> None:
        suite = DefenseSuite.for_category(SuiteCategory.TOOL_MISUSE)
        assert suite.category == "ASI-02"

    def test_create_for_identity_privilege(self) -> None:
        suite = DefenseSuite.for_category(SuiteCategory.IDENTITY_PRIVILEGE)
        assert suite.category == "ASI-03"

    def test_create_for_cascading_failures(self) -> None:
        suite = DefenseSuite.for_category(SuiteCategory.CASCADING_FAILURES)
        assert suite.category == "ASI-08"

    def test_create_for_rogue_agents(self) -> None:
        suite = DefenseSuite.for_category(SuiteCategory.ROGUE_AGENTS)
        assert suite.category == "ASI-10"


class TestDefenseSuiteDetect:
    def test_detect_returns_detection_result(self) -> None:
        suite = DefenseSuite(AlwaysSafeDetector())
        result = suite.detect({"text": "safe input"})
        assert isinstance(result, DetectionResult)

    def test_detect_safe_input(self) -> None:
        suite = DefenseSuite(AlwaysSafeDetector())
        result = suite.detect({"text": "safe input"})
        assert result.detected is False

    def test_detect_threat_input(self) -> None:
        suite = DefenseSuite(AlwaysThreatDetector())
        result = suite.detect({"text": "threat input"})
        assert result.detected is True

    def test_is_safe_convenience(self) -> None:
        suite = DefenseSuite(AlwaysSafeDetector())
        assert suite._detector.is_safe({"text": "safe"}) is True


class TestDefenseSuiteDefend:
    def test_defend_safe_input_returns_allowed(self) -> None:
        suite = DefenseSuite(AlwaysSafeDetector())
        result = suite.defend({"text": "safe input"})
        assert isinstance(result, DefenseSuiteResult)
        assert result.action_taken == "allowed"
        assert result.is_safe is True

    def test_defend_threat_input_default_blocks(self) -> None:
        suite = DefenseSuite(AlwaysThreatDetector(), default_action="block")
        result = suite.defend({"text": "threat"})
        assert result.action_taken == "blocked"
        assert result.is_safe is False

    def test_defend_threat_input_alert_action(self) -> None:
        suite = DefenseSuite(AlwaysThreatDetector(), default_action="alert")
        result = suite.defend({"text": "threat"})
        assert result.action_taken == "alerted"
        assert result.is_safe is True

    def test_defend_threat_input_sanitize_action(self) -> None:
        suite = DefenseSuite(AlwaysThreatDetector(), default_action="sanitize")
        result = suite.defend({"text": "threat"})
        assert result.action_taken == "sanitized"
        assert result.is_safe is True
        assert result.sanitized_input is not None

    def test_defend_result_has_latency(self) -> None:
        suite = DefenseSuite(AlwaysSafeDetector())
        result = suite.defend({"text": "input"})
        assert result.latency_ms >= 0.0

    def test_defend_to_dict_structure(self) -> None:
        suite = DefenseSuite(AlwaysSafeDetector())
        result = suite.defend({"text": "safe"})
        d = result.to_dict()
        assert "category" in d
        assert "action_taken" in d
        assert "is_safe" in d
        assert "detection" in d
        assert "latency_ms" in d


class TestDefenseSuiteSimulate:
    def test_simulate_returns_pairs(self) -> None:
        suite = DefenseSuite.for_category(SuiteCategory.GOAL_HIJACKING)
        results = suite.simulate()
        assert len(results) > 0
        for scenario, defense_result in results:
            assert isinstance(scenario, SimulationScenario)
            assert isinstance(defense_result, DefenseSuiteResult)

    def test_simulate_with_count_limit(self) -> None:
        suite = DefenseSuite.for_category(SuiteCategory.GOAL_HIJACKING)
        results = suite.simulate(count=2)
        assert len(results) <= 2

    def test_simulate_category_matches_suite(self) -> None:
        suite = DefenseSuite.for_category(SuiteCategory.ROGUE_AGENTS)
        results = suite.simulate()
        for scenario, _ in results:
            assert scenario.category == "ASI-10"


class TestGoalHijackingDetector:
    def setup_method(self) -> None:
        self.suite = DefenseSuite.for_category(SuiteCategory.GOAL_HIJACKING)

    def test_normal_query_is_safe(self) -> None:
        result = self.suite.detect({"text": "What is the weather today?"})
        assert result.detected is False

    def test_delimiter_pattern_detected(self) -> None:
        result = self.suite.detect({"text": "[SYSTEM] new instructions"})
        assert result.detected is True

    def test_bidi_override_detected(self) -> None:
        result = self.suite.detect({"text": "normal\u202ereversed"})
        assert result.detected is True

    def test_empty_text_is_safe(self) -> None:
        result = self.suite.detect({"text": ""})
        assert result.detected is False


class TestRogueAgentDetector:
    def setup_method(self) -> None:
        self.suite = DefenseSuite.for_category(SuiteCategory.ROGUE_AGENTS)

    def test_normal_metrics_are_safe(self) -> None:
        result = self.suite.detect({"action_count": 5, "token_usage": 1000, "error_rate": 0.01})
        assert result.detected is False

    def test_high_error_rate_detected(self) -> None:
        result = self.suite.detect({"action_count": 5, "token_usage": 1000, "error_rate": 0.9})
        assert result.detected is True
