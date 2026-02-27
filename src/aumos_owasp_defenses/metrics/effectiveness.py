"""DefenseMetrics — track TP, FP, TN, FN and compute precision, recall, F1.

Tracks detection outcomes and latency overhead for a single defense
implementation, enabling empirical measurement of defense effectiveness.

Example
-------
::

    from aumos_owasp_defenses.metrics.effectiveness import DefenseMetrics

    metrics = DefenseMetrics(defense_name="boundary-detector")
    metrics.record(predicted=True, actual=True, latency_ms=1.2)
    metrics.record(predicted=False, actual=True, latency_ms=0.8)
    metrics.record(predicted=True, actual=False, latency_ms=1.1)

    snapshot = metrics.snapshot()
    print(snapshot.precision, snapshot.recall, snapshot.f1_score)
"""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ConfusionMatrix:
    """Confusion matrix for binary classification.

    Attributes
    ----------
    true_positives:
        Threats correctly detected.
    false_positives:
        Safe inputs incorrectly flagged as threats.
    true_negatives:
        Safe inputs correctly passed.
    false_negatives:
        Threats incorrectly missed.
    """

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def total(self) -> int:
        """Total number of observations."""
        return self.true_positives + self.false_positives + self.true_negatives + self.false_negatives

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP). Returns 0.0 if no positive predictions."""
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator > 0 else 0.0

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN). Returns 0.0 if no actual positives."""
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """F1 = 2 * precision * recall / (precision + recall). Returns 0.0 if both are zero."""
        denom = self.precision + self.recall
        return 2 * self.precision * self.recall / denom if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """Accuracy = (TP + TN) / total. Returns 0.0 for empty data."""
        if self.total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total

    @property
    def false_positive_rate(self) -> float:
        """FPR = FP / (FP + TN). Returns 0.0 if no actual negatives."""
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator > 0 else 0.0

    @property
    def false_negative_rate(self) -> float:
        """FNR = FN / (FN + TP). Returns 0.0 if no actual positives."""
        denominator = self.false_negatives + self.true_positives
        return self.false_negatives / denominator if denominator > 0 else 0.0

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "total": self.total,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
        }


@dataclass(frozen=True)
class MetricsSnapshot:
    """Immutable snapshot of a DefenseMetrics state at a point in time.

    Attributes
    ----------
    defense_name:
        Name of the defense being measured.
    confusion_matrix:
        Current confusion matrix counts.
    precision:
        Fraction of positive detections that were correct.
    recall:
        Fraction of actual threats that were detected.
    f1_score:
        Harmonic mean of precision and recall.
    accuracy:
        Fraction of all observations correctly classified.
    mean_latency_ms:
        Average detection latency in milliseconds.
    p95_latency_ms:
        95th percentile detection latency in milliseconds.
    max_latency_ms:
        Maximum observed detection latency in milliseconds.
    total_observations:
        Total number of observations recorded.
    """

    defense_name: str
    confusion_matrix: ConfusionMatrix
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    mean_latency_ms: float
    p95_latency_ms: float
    max_latency_ms: float
    total_observations: int

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "defense_name": self.defense_name,
            "confusion_matrix": self.confusion_matrix.to_dict(),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "mean_latency_ms": round(self.mean_latency_ms, 3),
            "p95_latency_ms": round(self.p95_latency_ms, 3),
            "max_latency_ms": round(self.max_latency_ms, 3),
            "total_observations": self.total_observations,
        }


class DefenseMetrics:
    """Track TP, FP, TN, FN per defense and compute effectiveness metrics.

    Maintains a running record of detection outcomes and latency measurements.
    Call :meth:`snapshot` at any time to get a frozen view of current metrics.

    Parameters
    ----------
    defense_name:
        Human-readable identifier for the defense being measured.

    Example
    -------
    ::

        metrics = DefenseMetrics(defense_name="boundary-detector")

        # Record outcomes: predicted=True means "detected as threat"
        #                  actual=True means "it was actually a threat"
        metrics.record(predicted=True, actual=True, latency_ms=1.2)   # TP
        metrics.record(predicted=False, actual=True, latency_ms=0.8)  # FN
        metrics.record(predicted=True, actual=False, latency_ms=1.1)  # FP
        metrics.record(predicted=False, actual=False, latency_ms=0.5) # TN

        snapshot = metrics.snapshot()
        print(f"Precision: {snapshot.precision:.2%}")
        print(f"Recall: {snapshot.recall:.2%}")
        print(f"F1: {snapshot.f1_score:.2%}")
    """

    def __init__(self, defense_name: str) -> None:
        self.defense_name = defense_name
        self._true_positives = 0
        self._false_positives = 0
        self._true_negatives = 0
        self._false_negatives = 0
        self._latencies: list[float] = []

    @property
    def true_positives(self) -> int:
        """Current true positive count."""
        return self._true_positives

    @property
    def false_positives(self) -> int:
        """Current false positive count."""
        return self._false_positives

    @property
    def true_negatives(self) -> int:
        """Current true negative count."""
        return self._true_negatives

    @property
    def false_negatives(self) -> int:
        """Current false negative count."""
        return self._false_negatives

    @property
    def total_observations(self) -> int:
        """Total number of observations recorded."""
        return (
            self._true_positives
            + self._false_positives
            + self._true_negatives
            + self._false_negatives
        )

    def record(
        self,
        *,
        predicted: bool,
        actual: bool,
        latency_ms: float = 0.0,
    ) -> None:
        """Record a single detection outcome.

        Parameters
        ----------
        predicted:
            What the defense predicted: True means "detected as threat",
            False means "passed as safe".
        actual:
            Ground truth: True means "was actually a threat",
            False means "was actually safe".
        latency_ms:
            Wall-clock time for the detection call in milliseconds.
        """
        if predicted and actual:
            self._true_positives += 1
        elif predicted and not actual:
            self._false_positives += 1
        elif not predicted and actual:
            self._false_negatives += 1
        else:  # not predicted and not actual
            self._true_negatives += 1

        if latency_ms >= 0:
            self._latencies.append(float(latency_ms))

    def record_tp(self, latency_ms: float = 0.0) -> None:
        """Convenience: record a true positive."""
        self.record(predicted=True, actual=True, latency_ms=latency_ms)

    def record_fp(self, latency_ms: float = 0.0) -> None:
        """Convenience: record a false positive."""
        self.record(predicted=True, actual=False, latency_ms=latency_ms)

    def record_tn(self, latency_ms: float = 0.0) -> None:
        """Convenience: record a true negative."""
        self.record(predicted=False, actual=False, latency_ms=latency_ms)

    def record_fn(self, latency_ms: float = 0.0) -> None:
        """Convenience: record a false negative."""
        self.record(predicted=False, actual=True, latency_ms=latency_ms)

    def precision(self) -> float:
        """Current precision = TP / (TP + FP)."""
        denominator = self._true_positives + self._false_positives
        return self._true_positives / denominator if denominator > 0 else 0.0

    def recall(self) -> float:
        """Current recall = TP / (TP + FN)."""
        denominator = self._true_positives + self._false_negatives
        return self._true_positives / denominator if denominator > 0 else 0.0

    def f1_score(self) -> float:
        """Current F1 score = 2 * precision * recall / (precision + recall)."""
        p = self.precision()
        r = self.recall()
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def accuracy(self) -> float:
        """Current accuracy = (TP + TN) / total."""
        total = self.total_observations
        if total == 0:
            return 0.0
        return (self._true_positives + self._true_negatives) / total

    def mean_latency_ms(self) -> float:
        """Mean detection latency in milliseconds. Returns 0.0 if no observations."""
        return statistics.mean(self._latencies) if self._latencies else 0.0

    def p95_latency_ms(self) -> float:
        """95th percentile detection latency in milliseconds."""
        if not self._latencies:
            return 0.0
        sorted_latencies = sorted(self._latencies)
        idx = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]

    def max_latency_ms(self) -> float:
        """Maximum observed detection latency in milliseconds."""
        return max(self._latencies) if self._latencies else 0.0

    def confusion_matrix(self) -> ConfusionMatrix:
        """Return the current confusion matrix."""
        return ConfusionMatrix(
            true_positives=self._true_positives,
            false_positives=self._false_positives,
            true_negatives=self._true_negatives,
            false_negatives=self._false_negatives,
        )

    def reset(self) -> None:
        """Reset all counters and latency records to zero."""
        self._true_positives = 0
        self._false_positives = 0
        self._true_negatives = 0
        self._false_negatives = 0
        self._latencies.clear()

    def snapshot(self) -> MetricsSnapshot:
        """Return a frozen immutable snapshot of the current metrics state.

        Returns
        -------
        MetricsSnapshot
            Immutable snapshot with all computed metrics.
        """
        return MetricsSnapshot(
            defense_name=self.defense_name,
            confusion_matrix=self.confusion_matrix(),
            precision=self.precision(),
            recall=self.recall(),
            f1_score=self.f1_score(),
            accuracy=self.accuracy(),
            mean_latency_ms=self.mean_latency_ms(),
            p95_latency_ms=self.p95_latency_ms(),
            max_latency_ms=self.max_latency_ms(),
            total_observations=self.total_observations,
        )

    def time_detection(self, detection_fn: object, input_data: dict) -> tuple[bool, float]:
        """Time a detection function call and return (detected, latency_ms).

        Convenience helper for use in benchmarking loops.

        Parameters
        ----------
        detection_fn:
            Callable with detect(input_data) returning an object with .detected bool.
        input_data:
            Input to pass to the detection function.

        Returns
        -------
        tuple[bool, float]
            (was_detected, latency_ms)
        """
        start_ns = time.monotonic_ns()
        result = detection_fn.detect(input_data)  # type: ignore[union-attr]
        latency_ms = (time.monotonic_ns() - start_ns) / 1_000_000
        return bool(result.detected), latency_ms
