"""ASI-10: Rogue / Emergent Agent Behaviors — Drift Detector.

Detects behavioral drift from an established baseline using z-score
(standard deviation) analysis.  When a current observation deviates
from the baseline mean by more than a configured threshold (expressed in
standard deviations), a drift alert is generated.

No machine learning is involved.  The detector applies only classical
statistical outlier detection (z-score thresholding) against the running
statistics maintained by ``BaselineProfiler``.

Design notes
------------
* A z-score of 2.0 corresponds roughly to the 95th percentile of a normal
  distribution, meaning a 5% false-positive rate if the behavior is truly
  Gaussian.  Operators should tune the threshold based on acceptable false
  positive / false negative trade-offs.
* Metrics whose baselines are not yet mature (insufficient samples) are
  reported as ``INSUFFICIENT_DATA`` rather than raising false alerts.
* The detector is stateless; it reads from the profiler on every call
  and makes no internal state changes.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from enum import Enum

from aumos_owasp_defenses.defenses.asi10_rogue_agents.baseline_profiler import (
    BaselineProfiler,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Drift alert severity
# ---------------------------------------------------------------------------


class DriftSeverity(Enum):
    """Severity level for a detected drift event.

    * ``NONE``: Observation is within normal range.
    * ``WATCH``: Mild deviation — worth monitoring.
    * ``ALERT``: Significant deviation — investigate.
    * ``CRITICAL``: Extreme deviation — take immediate action.
    * ``INSUFFICIENT_DATA``: Baseline not yet mature; cannot assess.
    """

    NONE = "NONE"
    WATCH = "WATCH"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


# ---------------------------------------------------------------------------
# Per-metric drift finding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricDriftFinding:
    """Drift analysis result for a single metric.

    Attributes
    ----------
    metric_name:
        The behavioral metric that was evaluated.
    observed_value:
        The current observation being evaluated.
    baseline_mean:
        Mean from the established baseline.
    baseline_std_dev:
        Standard deviation from the established baseline.
    z_score:
        Signed z-score: ``(observed - mean) / std_dev``.
        ``None`` when std_dev is zero or baseline is immature.
    severity:
        Computed severity level.
    detail:
        Human-readable explanation of the finding.
    """

    metric_name: str
    observed_value: float
    baseline_mean: float
    baseline_std_dev: float
    z_score: float | None
    severity: DriftSeverity
    detail: str


# ---------------------------------------------------------------------------
# Aggregate drift check result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftCheckResult:
    """Aggregate result of a ``DriftDetector.check()`` call.

    Attributes
    ----------
    agent_id:
        Agent that was evaluated.
    has_drift:
        ``True`` when at least one metric has severity >= ``ALERT``.
    overall_severity:
        Highest severity across all metric findings.
    findings:
        Per-metric drift findings, sorted highest severity first.
    baseline_ready:
        ``True`` when the agent's baseline is mature enough for reliable
        drift detection.
    """

    agent_id: str
    has_drift: bool
    overall_severity: DriftSeverity
    findings: list[MetricDriftFinding]
    baseline_ready: bool


# ---------------------------------------------------------------------------
# Severity ordering helper
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[DriftSeverity, int] = {
    DriftSeverity.NONE: 0,
    DriftSeverity.WATCH: 1,
    DriftSeverity.ALERT: 2,
    DriftSeverity.CRITICAL: 3,
    DriftSeverity.INSUFFICIENT_DATA: -1,
}


def _max_severity(severities: list[DriftSeverity]) -> DriftSeverity:
    """Return the highest-priority severity from a list."""
    if not severities:
        return DriftSeverity.NONE
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s, -1))


# ---------------------------------------------------------------------------
# Drift detector
# ---------------------------------------------------------------------------


class DriftDetector:
    """Detects behavioral drift from a ``BaselineProfiler`` baseline.

    Parameters
    ----------
    profiler:
        The ``BaselineProfiler`` instance that holds the established baselines.
    watch_threshold:
        Z-score magnitude at or above which severity is ``WATCH``.
        Defaults to 1.5.
    alert_threshold:
        Z-score magnitude at or above which severity is ``ALERT``.
        Defaults to 2.5.
    critical_threshold:
        Z-score magnitude at or above which severity is ``CRITICAL``.
        Defaults to 4.0.

    Example
    -------
    >>> profiler = BaselineProfiler(min_samples=5)
    >>> for v in [10.0, 10.1, 9.9, 10.2, 9.8]:
    ...     profiler.record("agent-1", "calls_per_min", v)
    >>> detector = DriftDetector(profiler)
    >>> result = detector.check("agent-1", {"calls_per_min": 50.0})
    >>> result.has_drift
    True
    """

    def __init__(
        self,
        profiler: BaselineProfiler,
        watch_threshold: float = 1.5,
        alert_threshold: float = 2.5,
        critical_threshold: float = 4.0,
    ) -> None:
        self._profiler = profiler
        self._watch = watch_threshold
        self._alert = alert_threshold
        self._critical = critical_threshold

    def check(
        self,
        agent_id: str,
        current_observations: dict[str, float],
    ) -> DriftCheckResult:
        """Evaluate *current_observations* against the agent's baseline.

        Parameters
        ----------
        agent_id:
            The agent being evaluated.
        current_observations:
            Dict mapping metric name to current observed value.  Only
            metrics present in this dict are evaluated.  Extra metrics not
            in the baseline are reported as ``INSUFFICIENT_DATA``.

        Returns
        -------
        DriftCheckResult
        """
        baseline = self._profiler.get_baseline(agent_id)
        findings: list[MetricDriftFinding] = []

        for metric_name, observed_value in current_observations.items():
            metric_bl = baseline.metrics.get(metric_name)

            if metric_bl is None or not metric_bl.is_mature:
                finding = MetricDriftFinding(
                    metric_name=metric_name,
                    observed_value=observed_value,
                    baseline_mean=metric_bl.mean if metric_bl else 0.0,
                    baseline_std_dev=metric_bl.std_dev if metric_bl else 0.0,
                    z_score=None,
                    severity=DriftSeverity.INSUFFICIENT_DATA,
                    detail=(
                        f"Baseline for metric {metric_name!r} is not yet mature "
                        f"(samples: {metric_bl.sample_count if metric_bl else 0}). "
                        "Accumulate more observations before relying on drift detection."
                    ),
                )
                findings.append(finding)
                continue

            mean = metric_bl.mean
            std_dev = metric_bl.std_dev

            if std_dev == 0.0:
                # Zero variance baseline: any deviation from the mean is anomalous.
                if math.isclose(observed_value, mean):
                    finding = MetricDriftFinding(
                        metric_name=metric_name,
                        observed_value=observed_value,
                        baseline_mean=mean,
                        baseline_std_dev=std_dev,
                        z_score=0.0,
                        severity=DriftSeverity.NONE,
                        detail=f"Metric {metric_name!r} matches baseline exactly (zero variance).",
                    )
                else:
                    finding = MetricDriftFinding(
                        metric_name=metric_name,
                        observed_value=observed_value,
                        baseline_mean=mean,
                        baseline_std_dev=std_dev,
                        z_score=None,
                        severity=DriftSeverity.ALERT,
                        detail=(
                            f"Metric {metric_name!r} baseline has zero variance "
                            f"(mean={mean}) but observed {observed_value}. "
                            "Any deviation from a zero-variance baseline is suspicious."
                        ),
                    )
                findings.append(finding)
                continue

            z_score = (observed_value - mean) / std_dev
            abs_z = abs(z_score)

            if abs_z >= self._critical:
                severity = DriftSeverity.CRITICAL
                detail = (
                    f"CRITICAL drift on {metric_name!r}: z={z_score:.2f} "
                    f"(observed={observed_value:.4g}, mean={mean:.4g}, "
                    f"std_dev={std_dev:.4g}).  Investigate immediately."
                )
            elif abs_z >= self._alert:
                severity = DriftSeverity.ALERT
                detail = (
                    f"Significant drift on {metric_name!r}: z={z_score:.2f} "
                    f"(observed={observed_value:.4g}, mean={mean:.4g}, "
                    f"std_dev={std_dev:.4g})."
                )
            elif abs_z >= self._watch:
                severity = DriftSeverity.WATCH
                detail = (
                    f"Mild drift on {metric_name!r}: z={z_score:.2f} "
                    f"(observed={observed_value:.4g}, mean={mean:.4g}, "
                    f"std_dev={std_dev:.4g}).  Monitor closely."
                )
            else:
                severity = DriftSeverity.NONE
                detail = (
                    f"Metric {metric_name!r} within normal range: z={z_score:.2f}."
                )

            findings.append(
                MetricDriftFinding(
                    metric_name=metric_name,
                    observed_value=observed_value,
                    baseline_mean=mean,
                    baseline_std_dev=std_dev,
                    z_score=z_score,
                    severity=severity,
                    detail=detail,
                )
            )

        # Sort findings highest severity first.
        findings.sort(
            key=lambda f: _SEVERITY_ORDER.get(f.severity, -1),
            reverse=True,
        )

        all_severities = [f.severity for f in findings]
        overall = _max_severity(all_severities)
        has_drift = _SEVERITY_ORDER.get(overall, -1) >= _SEVERITY_ORDER[DriftSeverity.ALERT]

        if has_drift:
            logger.warning(
                "DRIFT_DETECTED agent=%r overall=%s", agent_id, overall.value
            )

        return DriftCheckResult(
            agent_id=agent_id,
            has_drift=has_drift,
            overall_severity=overall,
            findings=findings,
            baseline_ready=baseline.is_ready,
        )
