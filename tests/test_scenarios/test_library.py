"""Tests for ScenarioLibrary."""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.scenarios.library import (
    AttackCategory,
    ScenarioLibrary,
    ThreatScenario,
)


class TestThreatScenario:
    def test_frozen_is_hashable(self) -> None:
        scenario = ThreatScenario(
            id="PI-001",
            name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            owasp_asi="ASI-01",
            description="Test scenario.",
            detection_pattern="Check for patterns.",
            mitigation="Apply controls.",
        )
        assert scenario in {scenario}

    def test_to_dict_structure(self) -> None:
        scenario = ThreatScenario(
            id="TA-001",
            name="Tool Abuse",
            category=AttackCategory.TOOL_ABUSE,
            owasp_asi="ASI-02",
            description="Tool abuse scenario.",
            detection_pattern="Monitor tool calls.",
            mitigation="Validate all tool calls.",
            severity="high",
        )
        d = scenario.to_dict()
        assert d["id"] == "TA-001"
        assert d["category"] == "tool_abuse"
        assert d["owasp_asi"] == "ASI-02"
        assert d["severity"] == "high"


class TestScenarioLibrary:
    def setup_method(self) -> None:
        self.library = ScenarioLibrary()

    def test_total_count_at_least_50(self) -> None:
        assert self.library.total_count >= 50

    def test_get_by_id_known(self) -> None:
        scenario = self.library.get_by_id("PI-001")
        assert scenario is not None
        assert scenario.id == "PI-001"
        assert scenario.category == AttackCategory.PROMPT_INJECTION

    def test_get_by_id_unknown_returns_none(self) -> None:
        scenario = self.library.get_by_id("XX-999")
        assert scenario is None

    def test_get_by_category_prompt_injection(self) -> None:
        scenarios = self.library.get_by_category("prompt_injection")
        assert len(scenarios) >= 5
        for s in scenarios:
            assert s.category == AttackCategory.PROMPT_INJECTION

    def test_get_by_category_enum(self) -> None:
        scenarios = self.library.get_by_category(AttackCategory.TOOL_ABUSE)
        assert len(scenarios) >= 3
        for s in scenarios:
            assert s.category == AttackCategory.TOOL_ABUSE

    def test_get_by_owasp_asi_01(self) -> None:
        scenarios = self.library.get_by_owasp_asi("ASI-01")
        assert len(scenarios) >= 5
        for s in scenarios:
            assert s.owasp_asi == "ASI-01"

    def test_get_by_owasp_asi_case_insensitive_normalized(self) -> None:
        scenarios = self.library.get_by_owasp_asi("asi-01")
        assert len(scenarios) >= 5

    def test_get_by_severity_critical(self) -> None:
        scenarios = self.library.get_by_severity("critical")
        assert len(scenarios) >= 1
        for s in scenarios:
            assert s.severity == "critical"

    def test_get_by_severity_high(self) -> None:
        scenarios = self.library.get_by_severity("high")
        assert len(scenarios) >= 5
        for s in scenarios:
            assert s.severity == "high"

    def test_list_all_returns_all(self) -> None:
        all_scenarios = self.library.list_all()
        assert len(all_scenarios) == self.library.total_count

    def test_list_ids_sorted(self) -> None:
        ids = self.library.list_ids()
        assert ids == sorted(ids)

    def test_list_ids_count_matches_total(self) -> None:
        assert len(self.library.list_ids()) == self.library.total_count

    def test_search_by_keyword(self) -> None:
        results = self.library.search("prompt")
        assert len(results) > 0
        for s in results:
            assert "prompt" in s.name.lower() or "prompt" in s.description.lower()

    def test_search_case_insensitive(self) -> None:
        results_lower = self.library.search("injection")
        results_upper = self.library.search("INJECTION")
        assert len(results_lower) == len(results_upper)

    def test_search_no_results_for_nonsense(self) -> None:
        results = self.library.search("xyznonexistentkeyword123")
        assert len(results) == 0

    def test_all_scenarios_have_required_fields(self) -> None:
        for scenario in self.library.list_all():
            assert scenario.id != ""
            assert scenario.name != ""
            assert scenario.description != ""
            assert scenario.detection_pattern != ""
            assert scenario.mitigation != ""
            assert scenario.owasp_asi.startswith("ASI-")
            assert scenario.severity in {"critical", "high", "medium", "low"}

    def test_all_scenario_ids_are_unique(self) -> None:
        ids = self.library.list_ids()
        assert len(ids) == len(set(ids))

    def test_to_dict_structure(self) -> None:
        d = self.library.to_dict()
        assert "total_count" in d
        assert "scenarios" in d
        assert d["total_count"] == self.library.total_count

    def test_all_categories_represented(self) -> None:
        all_categories = {s.category for s in self.library.list_all()}
        assert AttackCategory.PROMPT_INJECTION in all_categories
        assert AttackCategory.TOOL_ABUSE in all_categories
        assert AttackCategory.DATA_EXFILTRATION in all_categories
