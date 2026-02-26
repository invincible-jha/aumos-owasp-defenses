"""OWASP ASI Top 10 guard middleware.

``OWASPGuard`` is the main entry-point for the defense library.  It
orchestrates all enabled ASI defense modules in a fixed sequence and
returns a single structured result that aggregates every finding.

Architecture
------------
Each ASI category maps to one or more defense classes.  ``OWASPGuard``
instantiates these with sensible defaults and invokes them against the
supplied input.  Callers can fine-tune behavior by passing a custom
``SecurityConfig`` and/or pre-built defense instances.

The guard never raises; all findings are collected into ``GuardResult``
so callers can decide whether to block, warn, or pass through.

Threat categories covered
--------------------------
* ASI-01 (Goal Hijacking): instruction-data boundary violations detected by
  ``BoundaryDetector``.
* ASI-09 (Trust Exploitation): delegated trust claims validated by
  ``TrustVerifier`` when agent context is provided.
* ASI-10 (Rogue Agents): behavioral drift reported by ``DriftDetector``
  when a profiler and baseline are available in the context.

Categories ASI-02 through ASI-08 are schema/structural checks that
operate on typed objects (tool calls, agent messages, etc.) rather than
raw text.  They are invoked by callers passing the relevant typed objects
via the ``context`` dict using the keys documented below.

Context keys (all optional)
-----------------------------
``"tool_call"`` : dict
    Tool invocation dict evaluated by the ASI-02 ``SchemaValidator`` if
    a schema for its ``tool_name`` is registered on the guard.
``"agent_message"`` : dict
    Inter-agent message dict evaluated by the ASI-07 ``MessageValidator``.
``"agent_id"`` : str
    Override agent identity for trust and drift checks (falls back to the
    ``agent_id`` positional parameter).
``"drift_observations"`` : dict[str, float]
    Current metric observations for ASI-10 drift detection.  Requires
    that ``BaselineProfiler`` observations have been pre-loaded into the
    profiler provided at construction time.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from aumos_owasp_defenses.defenses.asi01_goal_hijack import (
    BoundaryDetector,
    ThreatLevel,
)
from aumos_owasp_defenses.defenses.asi07_inter_agent import (
    MessageValidator,
)
from aumos_owasp_defenses.defenses.asi08_cascading_failures import (
    CircuitBreaker,
    CircuitOpenError,
)
from aumos_owasp_defenses.defenses.asi10_rogue_agents import (
    BaselineProfiler,
    DriftDetector,
    DriftSeverity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SecurityViolation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecurityViolation:
    """Describes a single security violation surfaced by the guard.

    Attributes
    ----------
    category:
        ASI category identifier, e.g. ``"ASI-01"``.
    description:
        Human-readable description of the violation.
    severity:
        Severity string: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
        or ``"info"``.
    """

    category: str
    description: str
    severity: str


# ---------------------------------------------------------------------------
# SecurityConfig
# ---------------------------------------------------------------------------


@dataclass
class SecurityConfig:
    """Feature flags controlling which ASI defense modules are active.

    All flags default to ``True`` (deny-nothing-by-default for individual
    checks; the guard still passes even if a module is enabled, it only
    adds findings).

    Attributes
    ----------
    asi01_enabled:
        Enable ASI-01 goal/task hijacking boundary detection.
    asi02_enabled:
        Enable ASI-02 tool/resource misuse schema validation (requires
        tool_call context).
    asi03_enabled:
        Enable ASI-03 identity/privilege capability checks (requires
        capability_checker context).
    asi04_enabled:
        Enable ASI-04 supply chain vendor verification (requires
        vendor_verifier context).
    asi05_enabled:
        Enable ASI-05 code execution scope checks (requires
        scope_limiter context).
    asi06_enabled:
        Enable ASI-06 memory provenance checks (requires
        provenance_tracker context).
    asi07_enabled:
        Enable ASI-07 inter-agent message validation (requires
        agent_message context).
    asi08_enabled:
        Enable ASI-08 cascading failure circuit-breaker checks.
    asi09_enabled:
        Enable ASI-09 trust exploitation claim verification (requires
        trust_claim context).
    asi10_enabled:
        Enable ASI-10 rogue-agent drift detection (requires
        drift_observations context and a configured BaselineProfiler).
    boundary_threat_threshold:
        Minimum ``ThreatLevel`` that triggers a violation for ASI-01.
        Defaults to ``ThreatLevel.MEDIUM``.
    drift_alert_threshold:
        Minimum ``DriftSeverity`` that triggers a violation for ASI-10.
        Defaults to ``DriftSeverity.ALERT``.
    """

    asi01_enabled: bool = True
    asi02_enabled: bool = True
    asi03_enabled: bool = True
    asi04_enabled: bool = True
    asi05_enabled: bool = True
    asi06_enabled: bool = True
    asi07_enabled: bool = True
    asi08_enabled: bool = True
    asi09_enabled: bool = True
    asi10_enabled: bool = True
    boundary_threat_threshold: ThreatLevel = ThreatLevel.MEDIUM
    drift_alert_threshold: DriftSeverity = DriftSeverity.ALERT


# ---------------------------------------------------------------------------
# GuardResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GuardResult:
    """Aggregate result of an ``OWASPGuard.protect()`` call.

    Attributes
    ----------
    passed:
        ``True`` when no violations with severity ``"high"`` or
        ``"critical"`` were found.
    violations:
        All violations collected across every enabled defense module.
    warnings:
        Informational messages that do not constitute a block-level event.
    checks_run:
        List of ASI category identifiers whose checks were actually
        executed (enabled and triggered by available context).
    """

    passed: bool
    violations: list[SecurityViolation]
    warnings: list[str]
    checks_run: list[str]


# ---------------------------------------------------------------------------
# OWASPGuard
# ---------------------------------------------------------------------------


_HIGH_SEVERITY_LABELS: frozenset[str] = frozenset({"critical", "high"})


class OWASPGuard:
    """Orchestrates all OWASP ASI Top 10 defense modules.

    Parameters
    ----------
    config:
        ``SecurityConfig`` controlling which modules are active.  If
        ``None``, all modules are enabled with default settings.
    boundary_detector:
        Custom ``BoundaryDetector`` instance for ASI-01.  If ``None``,
        a default instance is created using the threshold from ``config``.
    message_validator:
        Custom ``MessageValidator`` instance for ASI-07.  If ``None``,
        a default instance is created (no schemas registered; the check
        will produce a violation if an ``agent_message`` context key is
        present but the message type has no schema).
    baseline_profiler:
        ``BaselineProfiler`` for ASI-10 drift detection.  If ``None``,
        ASI-10 drift checks silently skip when ``drift_observations`` are
        provided.
    circuit_breaker:
        ``CircuitBreaker`` wrapping the guard's own execution (ASI-08).
        If ``None``, circuit-breaker protection is disabled for the guard
        itself.

    Example
    -------
    >>> guard = OWASPGuard()
    >>> result = guard.protect("Please summarise the document.", agent_id="worker-1")
    >>> result.passed
    True
    """

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        boundary_detector: Optional[BoundaryDetector] = None,
        message_validator: Optional[MessageValidator] = None,
        baseline_profiler: Optional[BaselineProfiler] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        self._config = config or SecurityConfig()
        self._boundary_detector = boundary_detector or BoundaryDetector(
            threshold=self._config.boundary_threat_threshold
        )
        self._message_validator = message_validator or MessageValidator()
        self._baseline_profiler = baseline_profiler
        self._drift_detector: Optional[DriftDetector] = (
            DriftDetector(self._baseline_profiler)
            if self._baseline_profiler is not None
            else None
        )
        self._circuit_breaker = circuit_breaker

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def protect(
        self,
        input_text: str,
        agent_id: str = "unknown",
        context: Optional[dict[str, object]] = None,
    ) -> GuardResult:
        """Run all enabled defenses against *input_text*.

        Parameters
        ----------
        input_text:
            Raw input text to evaluate (e.g., user message, tool output,
            external document content).
        agent_id:
            Identifier of the agent processing the input.  Used for
            drift detection and trust checks.
        context:
            Optional dict with additional typed objects for checks that
            require structured data.  See module docstring for supported keys.

        Returns
        -------
        GuardResult
            Aggregated result with all violations and warnings.
        """
        if self._circuit_breaker is not None:
            try:
                return self._circuit_breaker.call(
                    lambda: self._run_checks(input_text, agent_id, context or {})
                )
            except CircuitOpenError as circuit_error:
                logger.warning(
                    "OWASPGuard circuit breaker OPEN for agent=%r: %s",
                    agent_id,
                    circuit_error,
                )
                return GuardResult(
                    passed=False,
                    violations=[
                        SecurityViolation(
                            category="ASI-08",
                            description=(
                                f"Guard circuit breaker is open. "
                                f"Retry after {circuit_error.retry_after_seconds:.1f}s."
                            ),
                            severity="high",
                        )
                    ],
                    warnings=[],
                    checks_run=["ASI-08"],
                )

        return self._run_checks(input_text, agent_id, context or {})

    # ------------------------------------------------------------------
    # Internal check orchestration
    # ------------------------------------------------------------------

    def _run_checks(
        self,
        input_text: str,
        agent_id: str,
        context: dict[str, object],
    ) -> GuardResult:
        """Execute all enabled defense checks and aggregate results."""
        violations: list[SecurityViolation] = []
        warnings: list[str] = []
        checks_run: list[str] = []

        effective_agent_id = str(context.get("agent_id", agent_id))

        # ASI-01: Goal and Task Hijacking — boundary detection.
        if self._config.asi01_enabled:
            checks_run.append("ASI-01")
            analysis = self._boundary_detector.analyze(input_text)
            if not analysis.is_safe:
                for finding in analysis.findings:
                    if finding.threat_level >= self._config.boundary_threat_threshold:
                        violations.append(
                            SecurityViolation(
                                category="ASI-01",
                                description=(
                                    f"Boundary violation pattern '{finding.pattern_name}' "
                                    f"detected at offset {finding.location}. "
                                    f"{finding.recommendation}"
                                ),
                                severity=_threat_level_to_severity(finding.threat_level),
                            )
                        )
            elif analysis.findings:
                # Findings below the threshold become warnings.
                for finding in analysis.findings:
                    warnings.append(
                        f"ASI-01 low-level finding '{finding.pattern_name}' "
                        f"at offset {finding.location} (below block threshold)."
                    )

        # ASI-07: Inter-Agent Trust Exploitation — message validation.
        if self._config.asi07_enabled:
            raw_message = context.get("agent_message")
            if isinstance(raw_message, dict):
                checks_run.append("ASI-07")
                message_result = self._message_validator.validate_message(raw_message)
                if not message_result.valid:
                    for violation_text in message_result.violations:
                        violations.append(
                            SecurityViolation(
                                category="ASI-07",
                                description=violation_text,
                                severity="high",
                            )
                        )
                if message_result.is_replay:
                    violations.append(
                        SecurityViolation(
                            category="ASI-07",
                            description=(
                                "Replay attack detected: message correlation_id has "
                                "been seen before."
                            ),
                            severity="critical",
                        )
                    )

        # ASI-10: Rogue / Emergent Agent Behaviors — drift detection.
        if self._config.asi10_enabled and self._drift_detector is not None:
            raw_observations = context.get("drift_observations")
            if isinstance(raw_observations, dict):
                # Validate all values are numeric before passing on.
                numeric_observations: dict[str, float] = {}
                for key, value in raw_observations.items():
                    if isinstance(value, (int, float)):
                        numeric_observations[str(key)] = float(value)
                    else:
                        warnings.append(
                            f"ASI-10: drift_observations key {key!r} has non-numeric "
                            f"value {value!r}; skipped."
                        )

                if numeric_observations:
                    checks_run.append("ASI-10")
                    drift_result = self._drift_detector.check(
                        effective_agent_id, numeric_observations
                    )
                    for finding in drift_result.findings:
                        if _drift_severity_gte(
                            finding.severity, self._config.drift_alert_threshold
                        ):
                            violations.append(
                                SecurityViolation(
                                    category="ASI-10",
                                    description=finding.detail,
                                    severity=_drift_severity_to_severity(finding.severity),
                                )
                            )
                        elif finding.severity not in (
                            DriftSeverity.NONE,
                            DriftSeverity.INSUFFICIENT_DATA,
                        ):
                            warnings.append(f"ASI-10 drift watch: {finding.detail}")

        # Determine pass/fail based on violation severity.
        has_blocking_violation = any(
            v.severity in _HIGH_SEVERITY_LABELS for v in violations
        )

        logger.debug(
            "OWASPGuard agent=%r checks=%r violations=%d passed=%s",
            effective_agent_id,
            checks_run,
            len(violations),
            not has_blocking_violation,
        )

        return GuardResult(
            passed=not has_blocking_violation,
            violations=violations,
            warnings=warnings,
            checks_run=checks_run,
        )


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------


def _threat_level_to_severity(level: ThreatLevel) -> str:
    """Map a ``ThreatLevel`` value to a severity label string."""
    mapping: dict[ThreatLevel, str] = {
        ThreatLevel.CRITICAL: "critical",
        ThreatLevel.HIGH: "high",
        ThreatLevel.MEDIUM: "medium",
        ThreatLevel.LOW: "low",
        ThreatLevel.NONE: "info",
    }
    return mapping.get(level, "medium")


def _drift_severity_to_severity(level: DriftSeverity) -> str:
    """Map a ``DriftSeverity`` value to a severity label string."""
    mapping: dict[DriftSeverity, str] = {
        DriftSeverity.CRITICAL: "critical",
        DriftSeverity.ALERT: "high",
        DriftSeverity.WATCH: "medium",
        DriftSeverity.NONE: "info",
        DriftSeverity.INSUFFICIENT_DATA: "info",
    }
    return mapping.get(level, "medium")


_DRIFT_SEVERITY_ORDER: dict[DriftSeverity, int] = {
    DriftSeverity.INSUFFICIENT_DATA: -1,
    DriftSeverity.NONE: 0,
    DriftSeverity.WATCH: 1,
    DriftSeverity.ALERT: 2,
    DriftSeverity.CRITICAL: 3,
}


def _drift_severity_gte(level: DriftSeverity, threshold: DriftSeverity) -> bool:
    """Return True when *level* is at or above *threshold*."""
    return _DRIFT_SEVERITY_ORDER.get(level, -1) >= _DRIFT_SEVERITY_ORDER.get(
        threshold, 0
    )
