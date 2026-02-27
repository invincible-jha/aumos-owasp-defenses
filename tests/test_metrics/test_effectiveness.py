"""Tests for DefenseMetrics."""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.metrics.effectiveness import (
    ConfusionMatrix,
    DefenseMetrics,
    MetricsSnapshot,
)


class TestConfusionMatrix:
    def test_total_counts_all(self) -> None:
        cm = ConfusionMatrix(true_positives=3, false_positives=2, true_negatives=10, false_negatives=1)
        assert cm.total == 16

    def test_precision_correct(self) -> None:
        cm = ConfusionMatrix(true_positives=3, false_positives=1, true_negatives=5, false_negatives=1)
        # precision = 3 / (3 + 1) = 0.75
        assert cm.precision == pytest.approx(0.75)

    def test_precision_zero_when_no_positives(self) -> None:
        cm = ConfusionMatrix(true_positives=0, false_positives=0, true_negatives=5, false_negatives=2)
        assert cm.precision == 0.0

    def test_recall_correct(self) -> None:
        cm = ConfusionMatrix(true_positives=3, false_positives=1, true_negatives=5, false_negatives=1)
        # recall = 3 / (3 + 1) = 0.75
        assert cm.recall == pytest.approx(0.75)

    def test_recall_zero_when_no_actuals(self) -> None:
        cm = ConfusionMatrix(true_positives=0, false_positives=2, true_negatives=5, false_negatives=0)
        assert cm.recall == 0.0

    def test_f1_score_correct(self) -> None:
        cm = ConfusionMatrix(true_positives=3, false_positives=1, true_negatives=5, false_negatives=1)
        # F1 = 2 * 0.75 * 0.75 / (0.75 + 0.75) = 0.75
        assert cm.f1_score == pytest.approx(0.75)

    def test_f1_zero_when_precision_and_recall_zero(self) -> None:
        cm = ConfusionMatrix(true_positives=0, false_positives=0, true_negatives=5, false_negatives=3)
        assert cm.f1_score == 0.0

    def test_accuracy_correct(self) -> None:
        cm = ConfusionMatrix(true_positives=3, false_positives=1, true_negatives=5, false_negatives=1)
        # accuracy = (3 + 5) / 10 = 0.8
        assert cm.accuracy == pytest.approx(0.8)

    def test_accuracy_zero_for_empty(self) -> None:
        cm = ConfusionMatrix(true_positives=0, false_positives=0, true_negatives=0, false_negatives=0)
        assert cm.accuracy == 0.0

    def test_false_positive_rate(self) -> None:
        cm = ConfusionMatrix(true_positives=5, false_positives=2, true_negatives=8, false_negatives=1)
        # FPR = 2 / (2 + 8) = 0.2
        assert cm.false_positive_rate == pytest.approx(0.2)

    def test_false_negative_rate(self) -> None:
        cm = ConfusionMatrix(true_positives=5, false_positives=2, true_negatives=8, false_negatives=1)
        # FNR = 1 / (1 + 5) ≈ 0.1667
        assert cm.false_negative_rate == pytest.approx(1 / 6)

    def test_to_dict_has_all_keys(self) -> None:
        cm = ConfusionMatrix(true_positives=1, false_positives=1, true_negatives=1, false_negatives=1)
        d = cm.to_dict()
        expected_keys = {
            "true_positives", "false_positives", "true_negatives", "false_negatives",
            "total", "precision", "recall", "f1_score", "accuracy",
            "false_positive_rate", "false_negative_rate",
        }
        assert set(d.keys()) == expected_keys

    def test_is_frozen(self) -> None:
        cm = ConfusionMatrix(true_positives=1, false_positives=0, true_negatives=5, false_negatives=0)
        with pytest.raises(Exception):
            cm.true_positives = 2  # type: ignore[misc]


class TestDefenseMetrics:
    def setup_method(self) -> None:
        self.metrics = DefenseMetrics(defense_name="test-defense")

    def test_initial_state_all_zeros(self) -> None:
        assert self.metrics.true_positives == 0
        assert self.metrics.false_positives == 0
        assert self.metrics.true_negatives == 0
        assert self.metrics.false_negatives == 0
        assert self.metrics.total_observations == 0

    def test_record_true_positive(self) -> None:
        self.metrics.record(predicted=True, actual=True, latency_ms=1.0)
        assert self.metrics.true_positives == 1
        assert self.metrics.total_observations == 1

    def test_record_false_positive(self) -> None:
        self.metrics.record(predicted=True, actual=False, latency_ms=0.5)
        assert self.metrics.false_positives == 1

    def test_record_true_negative(self) -> None:
        self.metrics.record(predicted=False, actual=False, latency_ms=0.3)
        assert self.metrics.true_negatives == 1

    def test_record_false_negative(self) -> None:
        self.metrics.record(predicted=False, actual=True, latency_ms=0.8)
        assert self.metrics.false_negatives == 1

    def test_record_tp_convenience(self) -> None:
        self.metrics.record_tp(latency_ms=1.2)
        assert self.metrics.true_positives == 1

    def test_record_fp_convenience(self) -> None:
        self.metrics.record_fp(latency_ms=0.9)
        assert self.metrics.false_positives == 1

    def test_record_tn_convenience(self) -> None:
        self.metrics.record_tn(latency_ms=0.4)
        assert self.metrics.true_negatives == 1

    def test_record_fn_convenience(self) -> None:
        self.metrics.record_fn(latency_ms=0.6)
        assert self.metrics.false_negatives == 1

    def test_precision_computed_correctly(self) -> None:
        self.metrics.record_tp()
        self.metrics.record_tp()
        self.metrics.record_fp()
        # precision = 2 / (2 + 1) ≈ 0.667
        assert self.metrics.precision() == pytest.approx(2 / 3)

    def test_precision_zero_with_no_positives(self) -> None:
        self.metrics.record_tn()
        self.metrics.record_fn()
        assert self.metrics.precision() == 0.0

    def test_recall_computed_correctly(self) -> None:
        self.metrics.record_tp()
        self.metrics.record_fn()
        # recall = 1 / (1 + 1) = 0.5
        assert self.metrics.recall() == pytest.approx(0.5)

    def test_f1_score_computed_correctly(self) -> None:
        # Perfect precision and recall → F1 = 1.0
        for _ in range(5):
            self.metrics.record_tp()
        assert self.metrics.f1_score() == pytest.approx(1.0)

    def test_accuracy_computed_correctly(self) -> None:
        self.metrics.record_tp()
        self.metrics.record_tn()
        # accuracy = 2 / 2 = 1.0
        assert self.metrics.accuracy() == pytest.approx(1.0)

    def test_accuracy_zero_when_empty(self) -> None:
        assert self.metrics.accuracy() == 0.0

    def test_mean_latency_ms(self) -> None:
        self.metrics.record_tp(latency_ms=1.0)
        self.metrics.record_tp(latency_ms=3.0)
        assert self.metrics.mean_latency_ms() == pytest.approx(2.0)

    def test_mean_latency_zero_when_empty(self) -> None:
        assert self.metrics.mean_latency_ms() == 0.0

    def test_max_latency_ms(self) -> None:
        self.metrics.record_tp(latency_ms=1.0)
        self.metrics.record_tp(latency_ms=5.0)
        self.metrics.record_tp(latency_ms=2.0)
        assert self.metrics.max_latency_ms() == pytest.approx(5.0)

    def test_p95_latency_ms(self) -> None:
        for i in range(100):
            self.metrics.record_tp(latency_ms=float(i))
        # p95 of 0..99 should be around 94-95
        assert self.metrics.p95_latency_ms() >= 90.0

    def test_reset_clears_all_state(self) -> None:
        self.metrics.record_tp(latency_ms=1.0)
        self.metrics.record_fp(latency_ms=0.5)
        self.metrics.reset()
        assert self.metrics.total_observations == 0
        assert self.metrics.mean_latency_ms() == 0.0

    def test_confusion_matrix_returns_correct_counts(self) -> None:
        self.metrics.record_tp()
        self.metrics.record_fp()
        self.metrics.record_tn()
        self.metrics.record_tn()
        self.metrics.record_fn()
        cm = self.metrics.confusion_matrix()
        assert cm.true_positives == 1
        assert cm.false_positives == 1
        assert cm.true_negatives == 2
        assert cm.false_negatives == 1

    def test_snapshot_returns_frozen_snapshot(self) -> None:
        self.metrics.record_tp(latency_ms=1.0)
        self.metrics.record_tn(latency_ms=0.5)
        snapshot = self.metrics.snapshot()
        assert isinstance(snapshot, MetricsSnapshot)
        assert snapshot.defense_name == "test-defense"
        assert snapshot.total_observations == 2

    def test_snapshot_is_immutable(self) -> None:
        snapshot = self.metrics.snapshot()
        with pytest.raises(Exception):
            snapshot.precision = 0.5  # type: ignore[misc]

    def test_snapshot_to_dict_has_all_keys(self) -> None:
        self.metrics.record_tp(latency_ms=1.5)
        snapshot = self.metrics.snapshot()
        d = snapshot.to_dict()
        assert "defense_name" in d
        assert "confusion_matrix" in d
        assert "precision" in d
        assert "recall" in d
        assert "f1_score" in d
        assert "accuracy" in d
        assert "mean_latency_ms" in d
        assert "p95_latency_ms" in d
        assert "max_latency_ms" in d
        assert "total_observations" in d

    def test_multiple_observations_accurate(self) -> None:
        observations = [
            (True, True), (True, True), (True, False),
            (False, False), (False, False), (False, True),
        ]
        for predicted, actual in observations:
            self.metrics.record(predicted=predicted, actual=actual, latency_ms=1.0)
        assert self.metrics.total_observations == 6
        assert self.metrics.true_positives == 2
        assert self.metrics.false_positives == 1
        assert self.metrics.true_negatives == 2
        assert self.metrics.false_negatives == 1
