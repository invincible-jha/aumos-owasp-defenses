"""Tests for AttackSimulator."""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.defenses_suite.simulator import (
    AttackSimulator,
    SimulationScenario,
)


class TestSimulationScenario:
    def test_to_dict_structure(self) -> None:
        scenario = SimulationScenario(
            scenario_id="sim-ASI-01-000",
            category="ASI-01",
            label="benign_query",
            input_data={"text": "safe text"},
            expected_detection=False,
            notes="Normal query.",
        )
        d = scenario.to_dict()
        assert d["scenario_id"] == "sim-ASI-01-000"
        assert d["category"] == "ASI-01"
        assert d["expected_detection"] is False
        assert "text" in d["input_data"]


class TestAttackSimulator:
    def setup_method(self) -> None:
        self.simulator = AttackSimulator()

    def test_generate_scenarios_asi_01(self) -> None:
        scenarios = self.simulator.generate_scenarios("ASI-01")
        assert len(scenarios) > 0
        for s in scenarios:
            assert isinstance(s, SimulationScenario)
            assert s.category == "ASI-01"

    def test_generate_scenarios_asi_01_lowercase(self) -> None:
        scenarios = self.simulator.generate_scenarios("asi-01")
        assert len(scenarios) > 0

    def test_generate_scenarios_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="scenario templates"):
            self.simulator.generate_scenarios("ASI-99")

    def test_generate_scenarios_with_count_limit(self) -> None:
        scenarios = self.simulator.generate_scenarios("ASI-01", count=2)
        assert len(scenarios) <= 2

    def test_generate_scenarios_count_zero(self) -> None:
        scenarios = self.simulator.generate_scenarios("ASI-01", count=0)
        assert len(scenarios) == 0

    def test_scenarios_have_unique_ids(self) -> None:
        scenarios = self.simulator.generate_scenarios("ASI-01")
        ids = [s.scenario_id for s in scenarios]
        assert len(ids) == len(set(ids))

    def test_scenarios_have_input_data(self) -> None:
        scenarios = self.simulator.generate_scenarios("ASI-02")
        for s in scenarios:
            assert isinstance(s.input_data, dict)
            assert len(s.input_data) > 0

    def test_scenarios_expected_detection_is_bool(self) -> None:
        scenarios = self.simulator.generate_scenarios("ASI-10")
        for s in scenarios:
            assert isinstance(s.expected_detection, bool)

    def test_scenarios_have_labels(self) -> None:
        scenarios = self.simulator.generate_scenarios("ASI-01")
        for s in scenarios:
            assert s.label != ""

    def test_list_supported_categories(self) -> None:
        categories = self.simulator.list_supported_categories()
        assert len(categories) > 0
        assert "ASI-01" in categories
        assert all(c.startswith("ASI-") for c in categories)

    def test_generate_all_returns_dict(self) -> None:
        all_scenarios = self.simulator.generate_all()
        assert isinstance(all_scenarios, dict)
        assert len(all_scenarios) > 0
        for category, scenarios in all_scenarios.items():
            assert category.startswith("ASI-")
            assert len(scenarios) > 0

    def test_custom_seed_prefix(self) -> None:
        simulator = AttackSimulator(seed_prefix="test")
        scenarios = simulator.generate_scenarios("ASI-01")
        for s in scenarios:
            assert s.scenario_id.startswith("test-")

    def test_generate_all_categories_match_keys(self) -> None:
        all_scenarios = self.simulator.generate_all()
        for category, scenarios in all_scenarios.items():
            for s in scenarios:
                assert s.category == category

    def test_mixed_expected_detection_values(self) -> None:
        scenarios = self.simulator.generate_scenarios("ASI-01")
        detection_values = {s.expected_detection for s in scenarios}
        # Should have both True and False scenarios
        assert True in detection_values
        assert False in detection_values
