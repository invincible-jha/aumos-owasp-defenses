#!/usr/bin/env python3
"""Example: Rogue Agent Drift Detection (ASI-10)

Demonstrates establishing behaviour baselines, detecting metric
drift, and triggering alerts for rogue agent behaviour.

Usage:
    python examples/06_drift_detection.py

Requirements:
    pip install aumos-owasp-defenses
"""
from __future__ import annotations

import aumos_owasp_defenses as owasp
from aumos_owasp_defenses import (
    AgentBaseline,
    BaselineProfiler,
    DriftDetector,
    DriftSeverity,
    MetricBaseline,
)


def main() -> None:
    print(f"aumos-owasp-defenses version: {owasp.__version__}")

    # Step 1: Establish baselines for two agents
    baselines = [
        AgentBaseline(
            agent_id="nlp-agent",
            metric_baselines=[
                MetricBaseline(metric="tokens_per_call", mean=450, std=40),
                MetricBaseline(metric="error_rate", mean=0.02, std=0.005),
                MetricBaseline(metric="latency_ms", mean=320, std=30),
            ],
        ),
        AgentBaseline(
            agent_id="code-agent",
            metric_baselines=[
                MetricBaseline(metric="tokens_per_call", mean=800, std=80),
                MetricBaseline(metric="error_rate", mean=0.05, std=0.01),
                MetricBaseline(metric="latency_ms", mean=500, std=50),
            ],
        ),
    ]

    profiler = BaselineProfiler()
    for baseline in baselines:
        profiler.register(baseline)
    print(f"Baselines registered: {profiler.count()} agents")

    # Step 2: Simulate observations and detect drift
    detector = DriftDetector(profiler=profiler)

    agent_observations = [
        ("nlp-agent", "normal", {
            "tokens_per_call": 460, "error_rate": 0.021, "latency_ms": 330
        }),
        ("nlp-agent", "anomalous-tokens", {
            "tokens_per_call": 8500, "error_rate": 0.021, "latency_ms": 330
        }),
        ("nlp-agent", "anomalous-all", {
            "tokens_per_call": 9000, "error_rate": 0.80, "latency_ms": 3000
        }),
        ("code-agent", "normal", {
            "tokens_per_call": 820, "error_rate": 0.048, "latency_ms": 510
        }),
        ("code-agent", "high-error", {
            "tokens_per_call": 850, "error_rate": 0.90, "latency_ms": 520
        }),
    ]

    print("\nDrift detection results:")
    for agent_id, label, obs in agent_observations:
        result = detector.check(agent_id=agent_id, metrics=obs)
        icon = f"DRIFT[{result.severity.value}]" if result.is_drifted else "NORMAL"
        print(f"  [{icon}] {agent_id}/{label}")
        if result.is_drifted:
            for finding in result.findings:
                print(f"    Metric '{finding.metric}': "
                      f"observed={finding.observed_value:.1f}, "
                      f"baseline_mean={finding.baseline_mean:.1f}, "
                      f"z_score={finding.z_score:.2f}")

    # Step 3: Summary of drift checks
    summary = detector.summary()
    print(f"\nDrift summary: {summary.total_checks} checks, "
          f"{summary.drift_count} drifts detected, "
          f"drift_rate={summary.drift_rate:.0%}")


if __name__ == "__main__":
    main()
