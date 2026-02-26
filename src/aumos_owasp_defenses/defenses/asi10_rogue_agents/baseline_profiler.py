"""ASI-10: Rogue / Emergent Agent Behaviors — Baseline Profiler.

Builds and maintains a statistical behavioral baseline for an agent by
recording observations of its behavior over time.  The baseline is used
by ``DriftDetector`` to identify abnormal behavioral patterns.

Observations are numeric measurements of behavioral signals:

* Tool call frequency per unit time
* Average prompt length
* Response latency
* Error rate
* Number of unique tools called per session
* Memory read/write ratio

The profiler accumulates rolling windows of observations and exposes
summary statistics (mean, standard deviation) per metric.  No ML model
is involved; all statistics are computed from first principles using
Welford's online algorithm for numerical stability.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Online statistics accumulator (Welford's algorithm)
# ---------------------------------------------------------------------------


@dataclass
class _OnlineStat:
    """Maintains running mean and variance using Welford's online algorithm.

    This approach is numerically stable for large sample counts and
    does not require storing all raw observations.
    """

    count: int = 0
    mean: float = 0.0
    _m2: float = 0.0      # sum of squared deviations from the mean

    def update(self, value: float) -> None:
        """Incorporate a new observation."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self._m2 += delta * delta2

    @property
    def variance(self) -> float:
        """Population variance (returns 0.0 if fewer than 2 observations)."""
        return self._m2 / self.count if self.count >= 2 else 0.0

    @property
    def std_dev(self) -> float:
        """Population standard deviation."""
        return math.sqrt(self.variance)

    def to_dict(self) -> dict[str, float]:
        """Serialise to a plain dict."""
        return {
            "count": float(self.count),
            "mean": self.mean,
            "std_dev": self.std_dev,
        }


# ---------------------------------------------------------------------------
# Baseline snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricBaseline:
    """Snapshot of the statistical baseline for a single metric.

    Attributes
    ----------
    metric_name:
        Name of the behavioral metric.
    sample_count:
        Number of observations recorded.
    mean:
        Sample mean.
    std_dev:
        Population standard deviation.
    is_mature:
        ``True`` when enough observations have been recorded for the
        baseline to be considered reliable (>= ``min_samples``).
    """

    metric_name: str
    sample_count: int
    mean: float
    std_dev: float
    is_mature: bool


@dataclass(frozen=True)
class AgentBaseline:
    """Full behavioral baseline for a single agent.

    Attributes
    ----------
    agent_id:
        The agent this baseline describes.
    metrics:
        Dict mapping metric name to its ``MetricBaseline`` snapshot.
    is_ready:
        ``True`` when all tracked metrics are mature.
    """

    agent_id: str
    metrics: dict[str, MetricBaseline]
    is_ready: bool


# ---------------------------------------------------------------------------
# Profiler
# ---------------------------------------------------------------------------


class BaselineProfiler:
    """Records behavioral observations and builds baselines for agents.

    Parameters
    ----------
    min_samples:
        Minimum number of observations required before a metric baseline
        is considered mature enough for drift detection.  Defaults to 30.

    Example
    -------
    >>> profiler = BaselineProfiler(min_samples=5)
    >>> for value in [1.0, 1.1, 0.9, 1.05, 0.95]:
    ...     profiler.record("agent-1", "tool_calls_per_min", value)
    >>> baseline = profiler.get_baseline("agent-1")
    >>> baseline.is_ready
    True
    """

    def __init__(self, min_samples: int = 30) -> None:
        self._min_samples = min_samples
        # agent_id -> metric_name -> _OnlineStat
        self._stats: dict[str, dict[str, _OnlineStat]] = {}

    def record(self, agent_id: str, metric_name: str, value: float) -> None:
        """Record a single behavioral observation.

        Parameters
        ----------
        agent_id:
            Identifier of the agent being profiled.
        metric_name:
            Name of the behavioral metric being observed (e.g.,
            ``"tool_calls_per_min"``, ``"avg_prompt_length"``).
        value:
            Numeric observation value.
        """
        if agent_id not in self._stats:
            self._stats[agent_id] = {}
        if metric_name not in self._stats[agent_id]:
            self._stats[agent_id][metric_name] = _OnlineStat()
        self._stats[agent_id][metric_name].update(value)
        logger.debug(
            "Recorded agent=%r metric=%r value=%f count=%d",
            agent_id,
            metric_name,
            value,
            self._stats[agent_id][metric_name].count,
        )

    def get_baseline(self, agent_id: str) -> AgentBaseline:
        """Return the current baseline snapshot for *agent_id*.

        Parameters
        ----------
        agent_id:
            Agent to retrieve the baseline for.

        Returns
        -------
        AgentBaseline
            Contains per-metric snapshots.  If no observations have been
            recorded, returns an empty baseline with ``is_ready=False``.
        """
        agent_stats = self._stats.get(agent_id, {})
        metrics: dict[str, MetricBaseline] = {}

        for metric_name, stat in agent_stats.items():
            is_mature = stat.count >= self._min_samples
            metrics[metric_name] = MetricBaseline(
                metric_name=metric_name,
                sample_count=stat.count,
                mean=stat.mean,
                std_dev=stat.std_dev,
                is_mature=is_mature,
            )

        is_ready = bool(metrics) and all(m.is_mature for m in metrics.values())

        return AgentBaseline(
            agent_id=agent_id,
            metrics=metrics,
            is_ready=is_ready,
        )

    def get_metric_stat(self, agent_id: str, metric_name: str) -> _OnlineStat | None:
        """Return the raw ``_OnlineStat`` for a specific metric (internal use).

        Parameters
        ----------
        agent_id:
            Agent identifier.
        metric_name:
            Metric name.

        Returns
        -------
        _OnlineStat | None
            ``None`` if not found.
        """
        return self._stats.get(agent_id, {}).get(metric_name)

    def reset(self, agent_id: str) -> None:
        """Clear all observations for *agent_id*.

        Parameters
        ----------
        agent_id:
            Agent whose data to reset.
        """
        self._stats.pop(agent_id, None)

    def known_agents(self) -> list[str]:
        """Return a list of agents for which data has been recorded.

        Returns
        -------
        list[str]
        """
        return list(self._stats)
