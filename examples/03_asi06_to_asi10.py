#!/usr/bin/env python3
"""Example: ASI-06 through ASI-10 Defenses

Demonstrates the second five OWASP ASI Top 10 defensive controls:
memory poisoning, inter-agent trust, cascading failures, trust
exploitation, and rogue agent detection.

Usage:
    python examples/03_asi06_to_asi10.py

Requirements:
    pip install aumos-owasp-defenses
"""
from __future__ import annotations

import aumos_owasp_defenses as owasp
from aumos_owasp_defenses import (
    AgentBaseline,
    AgentTrustLevel,
    AgentTrustProfile,
    BaselineProfiler,
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    DriftDetector,
    FieldSpec,
    MessageSchema,
    MessageValidator,
    MetricBaseline,
    ProvenanceRecord,
    ProvenanceTracker,
    SourceTrustLevel,
    TrustTier,
    TrustVerifier,
)


def main() -> None:
    print(f"aumos-owasp-defenses version: {owasp.__version__}")

    # ASI-06: Memory/context provenance tracking
    tracker = ProvenanceTracker()
    records = [
        ProvenanceRecord(content_id="ctx-001", source="user-input",
                         trust_level=SourceTrustLevel.HIGH),
        ProvenanceRecord(content_id="ctx-002", source="external-api",
                         trust_level=SourceTrustLevel.MEDIUM),
        ProvenanceRecord(content_id="ctx-003", source="unknown",
                         trust_level=SourceTrustLevel.LOW),
    ]
    for r in records:
        tracker.record(r)
    chain_result = tracker.verify_chain(["ctx-001", "ctx-002", "ctx-003"])
    print(f"ASI-06 Provenance chain: trusted={chain_result.trusted}, "
          f"min_trust={chain_result.minimum_trust_level.value}")

    # ASI-07: Inter-agent message validation
    schema = MessageSchema(fields=[
        FieldSpec("sender_id", "string", required=True),
        FieldSpec("action", "string", required=True),
        FieldSpec("payload", "object", required=False),
    ])
    validator = MessageValidator(schemas={"agent-task": schema})
    print("\nASI-07 Inter-Agent Message Validation:")
    messages = [
        {"sender_id": "agent-alpha", "action": "summarise", "payload": {}},
        {"action": "delete"},  # missing sender_id
    ]
    for msg in messages:
        result = validator.validate(schema_name="agent-task", message=msg)
        print(f"  [{'VALID' if result.is_valid else 'INVALID'}] {msg}")

    # ASI-08: Circuit breaker for cascading failures
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30)
    print(f"\nASI-08 Circuit Breaker (threshold=3):")
    for i in range(5):
        try:
            with breaker.guard():
                if i < 3:
                    raise ConnectionError("downstream service unavailable")
                print(f"  Call {i + 1}: SUCCESS")
        except CircuitOpenError:
            print(f"  Call {i + 1}: BLOCKED (circuit open)")
        except ConnectionError as error:
            print(f"  Call {i + 1}: FAILED ({error})")
    print(f"  Circuit state: {breaker.state.value}")

    # ASI-09: Trust verification and escalation checks
    profile = AgentTrustProfile(
        agent_id="external-agent",
        tier=TrustTier.UNTRUSTED,
        capabilities=[],
    )
    verifier = TrustVerifier(profiles=[profile])
    print("\nASI-09 Trust Verification:")
    result = verifier.verify_claim(
        agent_id="external-agent",
        claimed_capability="admin-access",
    )
    print(f"  Claim verified: {result.verified} (tier={profile.tier.value})")

    # ASI-10: Rogue agent drift detection
    baseline = AgentBaseline(
        agent_id="production-agent",
        metric_baselines=[
            MetricBaseline(metric="tokens_per_call", mean=500, std=50),
            MetricBaseline(metric="error_rate", mean=0.02, std=0.005),
        ],
    )
    profiler = BaselineProfiler()
    profiler.register(baseline)
    detector = DriftDetector(profiler=profiler)
    print("\nASI-10 Rogue Agent Drift:")
    observations = [
        {"tokens_per_call": 520, "error_rate": 0.021},   # normal
        {"tokens_per_call": 9000, "error_rate": 0.50},   # drifted
    ]
    for obs in observations:
        result = detector.check(agent_id="production-agent", metrics=obs)
        print(f"  Drifted: {result.is_drifted} | "
              f"Severity: {result.severity.value if result.is_drifted else 'none'}")


if __name__ == "__main__":
    main()
