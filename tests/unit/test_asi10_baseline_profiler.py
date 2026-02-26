"""Tests for ASI-10 BaselineProfiler and DriftDetector."""
from __future__ import annotations

import math

import pytest

from aumos_owasp_defenses.defenses.asi10_rogue_agents.baseline_profiler import (
    AgentBaseline,
    BaselineProfiler,
    MetricBaseline,
    _OnlineStat,
)
from aumos_owasp_defenses.defenses.asi10_rogue_agents.drift_detector import (
    DriftCheckResult,
    DriftDetector,
    DriftSeverity,
    MetricDriftFinding,
    _max_severity,
)


# ---------------------------------------------------------------------------
# _OnlineStat — Welford's algorithm
# ---------------------------------------------------------------------------


class TestOnlineStat:
    def test_initial_state(self) -> None:
        stat = _OnlineStat()
        assert stat.count == 0
        assert stat.mean == 0.0
        assert stat.variance == 0.0
        assert stat.std_dev == 0.0

    def test_single_value(self) -> None:
        stat = _OnlineStat()
        stat.update(5.0)
        assert stat.count == 1
        assert stat.mean == pytest.approx(5.0)
        assert stat.variance == 0.0

    def test_two_values(self) -> None:
        stat = _OnlineStat()
        stat.update(2.0)
        stat.update(4.0)
        assert stat.mean == pytest.approx(3.0)
        assert stat.variance == pytest.approx(1.0)

    def test_uniform_values_zero_variance(self) -> None:
        stat = _OnlineStat()
        for _ in range(10):
            stat.update(7.0)
        assert stat.mean == pytest.approx(7.0)
        assert stat.variance == pytest.approx(0.0)
        assert stat.std_dev == pytest.approx(0.0)

    def test_std_dev_matches_sqrt_variance(self) -> None:
        stat = _OnlineStat()
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            stat.update(v)
        assert stat.std_dev == pytest.approx(math.sqrt(stat.variance))

    def test_to_dict(self) -> None:
        stat = _OnlineStat()
        stat.update(10.0)
        d = stat.to_dict()
        assert d["count"] == 1.0
        assert d["mean"] == pytest.approx(10.0)
        assert "std_dev" in d


# ---------------------------------------------------------------------------
# BaselineProfiler — record
# ---------------------------------------------------------------------------


class TestBaselineProfilerRecord:
    def test_record_new_agent_and_metric(self) -> None:
        profiler = BaselineProfiler(min_samples=5)
        profiler.record("agent-1", "tool_calls", 3.0)
        assert "agent-1" in profiler.known_agents()

    def test_record_multiple_metrics(self) -> None:
        profiler = BaselineProfiler(min_samples=5)
        profiler.record("agent-1", "calls", 1.0)
        profiler.record("agent-1", "latency", 100.0)
        baseline = profiler.get_baseline("agent-1")
        assert "calls" in baseline.metrics
        assert "latency" in baseline.metrics

    def test_record_multiple_agents(self) -> None:
        profiler = BaselineProfiler()
        profiler.record("agent-1", "metric", 1.0)
        profiler.record("agent-2", "metric", 2.0)
        assert set(profiler.known_agents()) == {"agent-1", "agent-2"}


# ---------------------------------------------------------------------------
# BaselineProfiler — get_baseline
# ---------------------------------------------------------------------------


class TestGetBaseline:
    def test_unknown_agent_returns_empty_not_ready(self) -> None:
        profiler = BaselineProfiler()
        baseline = profiler.get_baseline("unknown")
        assert baseline.is_ready is False
        assert baseline.metrics == {}

    def test_baseline_not_mature_below_min_samples(self) -> None:
        profiler = BaselineProfiler(min_samples=30)
        for i in range(10):
            profiler.record("agent-1", "calls", float(i))
        baseline = profiler.get_baseline("agent-1")
        assert baseline.is_ready is False
        assert baseline.metrics["calls"].is_mature is False

    def test_baseline_mature_at_min_samples(self) -> None:
        profiler = BaselineProfiler(min_samples=5)
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            profiler.record("agent-1", "calls", v)
        baseline = profiler.get_baseline("agent-1")
        assert baseline.is_ready is True
        assert baseline.metrics["calls"].is_mature is True

    def test_baseline_not_ready_if_any_metric_immature(self) -> None:
        profiler = BaselineProfiler(min_samples=5)
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            profiler.record("agent-1", "calls", v)
        profiler.record("agent-1", "latency", 100.0)  # Only 1 sample
        baseline = profiler.get_baseline("agent-1")
        assert baseline.is_ready is False

    def test_metric_baseline_stats(self) -> None:
        profiler = BaselineProfiler(min_samples=3)
        for v in [10.0, 20.0, 30.0]:
            profiler.record("agent-1", "metric", v)
        baseline = profiler.get_baseline("agent-1")
        mb = baseline.metrics["metric"]
        assert mb.sample_count == 3
        assert mb.mean == pytest.approx(20.0)
        assert mb.std_dev > 0

    def test_agent_baseline_id(self) -> None:
        profiler = BaselineProfiler()
        profiler.record("my-agent", "m", 1.0)
        baseline = profiler.get_baseline("my-agent")
        assert baseline.agent_id == "my-agent"


# ---------------------------------------------------------------------------
# BaselineProfiler — get_metric_stat and reset
# ---------------------------------------------------------------------------


class TestGetMetricStatAndReset:
    def test_get_metric_stat_existing(self) -> None:
        profiler = BaselineProfiler()
        profiler.record("agent-1", "calls", 5.0)
        stat = profiler.get_metric_stat("agent-1", "calls")
        assert stat is not None
        assert stat.count == 1

    def test_get_metric_stat_missing_agent(self) -> None:
        profiler = BaselineProfiler()
        assert profiler.get_metric_stat("missing", "calls") is None

    def test_get_metric_stat_missing_metric(self) -> None:
        profiler = BaselineProfiler()
        profiler.record("agent-1", "calls", 1.0)
        assert profiler.get_metric_stat("agent-1", "latency") is None

    def test_reset_clears_agent(self) -> None:
        profiler = BaselineProfiler()
        profiler.record("agent-1", "calls", 1.0)
        profiler.reset("agent-1")
        assert "agent-1" not in profiler.known_agents()

    def test_reset_nonexistent_safe(self) -> None:
        profiler = BaselineProfiler()
        profiler.reset("ghost")  # Should not raise


# ---------------------------------------------------------------------------
# DriftDetector — _max_severity helper
# ---------------------------------------------------------------------------


class TestMaxSeverity:
    def test_empty_list_returns_none(self) -> None:
        assert _max_severity([]) == DriftSeverity.NONE

    def test_returns_highest(self) -> None:
        severities = [DriftSeverity.NONE, DriftSeverity.ALERT, DriftSeverity.WATCH]
        assert _max_severity(severities) == DriftSeverity.ALERT

    def test_critical_is_highest(self) -> None:
        severities = [DriftSeverity.CRITICAL, DriftSeverity.ALERT]
        assert _max_severity(severities) == DriftSeverity.CRITICAL

    def test_insufficient_data_is_lowest(self) -> None:
        severities = [DriftSeverity.INSUFFICIENT_DATA, DriftSeverity.NONE]
        assert _max_severity(severities) == DriftSeverity.NONE


# ---------------------------------------------------------------------------
# DriftDetector — check with immature baseline
# ---------------------------------------------------------------------------


class TestDriftDetectorImmatureBaseline:
    def test_immature_baseline_produces_insufficient_data(self) -> None:
        profiler = BaselineProfiler(min_samples=30)
        profiler.record("agent-1", "calls", 5.0)
        detector = DriftDetector(profiler)
        result = detector.check("agent-1", {"calls": 100.0})
        assert result.baseline_ready is False
        assert len(result.findings) == 1
        assert result.findings[0].severity == DriftSeverity.INSUFFICIENT_DATA
        assert result.findings[0].z_score is None

    def test_unknown_agent_produces_insufficient_data(self) -> None:
        profiler = BaselineProfiler(min_samples=5)
        detector = DriftDetector(profiler)
        result = detector.check("ghost", {"calls": 10.0})
        assert result.findings[0].severity == DriftSeverity.INSUFFICIENT_DATA


# ---------------------------------------------------------------------------
# DriftDetector — check with mature baseline
# ---------------------------------------------------------------------------


def _build_detector(
    metric_values: list[float],
    metric_name: str = "calls",
    agent_id: str = "agent-1",
    min_samples: int = 5,
    watch: float = 1.5,
    alert: float = 2.5,
    critical: float = 4.0,
) -> tuple[DriftDetector, str]:
    profiler = BaselineProfiler(min_samples=min_samples)
    for v in metric_values:
        profiler.record(agent_id, metric_name, v)
    detector = DriftDetector(profiler, watch, alert, critical)
    return detector, agent_id


class TestDriftDetectorMatureBaseline:
    def test_within_normal_range(self) -> None:
        values = [10.0, 10.1, 9.9, 10.2, 9.8]
        detector, agent_id = _build_detector(values)
        result = detector.check(agent_id, {"calls": 10.0})
        assert result.baseline_ready is True
        assert result.has_drift is False
        assert result.findings[0].severity == DriftSeverity.NONE

    def test_critical_drift_detected(self) -> None:
        values = [10.0] * 10
        # std_dev is 0 for constant values — any deviation => ALERT
        detector, agent_id = _build_detector(values, min_samples=10)
        result = detector.check(agent_id, {"calls": 50.0})
        assert result.has_drift is True
        finding = result.findings[0]
        assert finding.severity in (DriftSeverity.ALERT, DriftSeverity.CRITICAL)

    def test_watch_level_drift(self) -> None:
        # Build a baseline with known std_dev and produce z≈2.0 (WATCH)
        values = [10.0, 10.0, 12.0, 8.0, 10.0]  # mean=10, some variance
        profiler = BaselineProfiler(min_samples=5)
        for v in values:
            profiler.record("agent-1", "calls", v)
        baseline = profiler.get_baseline("agent-1")
        mean = baseline.metrics["calls"].mean
        std_dev = baseline.metrics["calls"].std_dev
        # Produce a value at z ≈ 1.8 (between watch=1.5 and alert=2.5)
        watch_value = mean + 1.8 * std_dev
        detector = DriftDetector(profiler, watch_threshold=1.5, alert_threshold=2.5)
        result = detector.check("agent-1", {"calls": watch_value})
        assert result.findings[0].severity == DriftSeverity.WATCH

    def test_zero_variance_exact_match_is_none(self) -> None:
        values = [10.0, 10.0, 10.0, 10.0, 10.0]
        detector, agent_id = _build_detector(values)
        result = detector.check(agent_id, {"calls": 10.0})
        assert result.findings[0].severity == DriftSeverity.NONE
        assert result.findings[0].z_score == pytest.approx(0.0)

    def test_zero_variance_deviation_is_alert(self) -> None:
        values = [10.0, 10.0, 10.0, 10.0, 10.0]
        detector, agent_id = _build_detector(values)
        result = detector.check(agent_id, {"calls": 11.0})
        assert result.findings[0].severity == DriftSeverity.ALERT
        assert result.findings[0].z_score is None

    def test_findings_sorted_by_severity(self) -> None:
        profiler = BaselineProfiler(min_samples=5)
        for v in [10.0, 10.0, 10.0, 10.0, 10.0]:
            profiler.record("agent-1", "metric_a", v)
            profiler.record("agent-1", "metric_b", v)
        detector = DriftDetector(profiler)
        result = detector.check("agent-1", {
            "metric_a": 10.0,  # NONE (exact)
            "metric_b": 50.0,  # ALERT (deviation)
        })
        # Higher severity should be first
        severities = [f.severity for f in result.findings]
        from aumos_owasp_defenses.defenses.asi10_rogue_agents.drift_detector import _SEVERITY_ORDER
        orders = [_SEVERITY_ORDER.get(s, -1) for s in severities]
        assert orders == sorted(orders, reverse=True)

    def test_result_has_correct_agent_id(self) -> None:
        profiler = BaselineProfiler(min_samples=3)
        for v in [1.0, 2.0, 3.0]:
            profiler.record("my-agent", "m", v)
        detector = DriftDetector(profiler)
        result = detector.check("my-agent", {"m": 2.0})
        assert result.agent_id == "my-agent"

    def test_z_score_positive_for_high_value(self) -> None:
        values = [10.0, 11.0, 9.0, 10.5, 9.5]
        detector, agent_id = _build_detector(values)
        baseline = detector._profiler.get_baseline(agent_id)
        mean = baseline.metrics["calls"].mean
        std_dev = baseline.metrics["calls"].std_dev
        high_value = mean + 3 * std_dev
        result = detector.check(agent_id, {"calls": high_value})
        assert result.findings[0].z_score is not None
        assert result.findings[0].z_score > 0
