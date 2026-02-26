"""Scanner — AgentScanner runs all ten ASI defense checks against an agent config.

The scanner accepts an ``agent_config`` dictionary that describes an agent's
declared properties (tools, capabilities, memory, etc.) and evaluates each
ASI category against the configuration using structural analysis.

It does **not** execute the agent; it analyses the *configuration* for
missing or insufficient defenses.  Think of it as a linter or audit tool
for agent configurations.

Agent config format (all keys optional)
----------------------------------------
::

    {
        "agent_id": "my-agent",
        "description": "Customer support assistant",
        "system_prompt": "You are a helpful assistant...",
        "tools": [
            {"name": "search_web", "schema": {...}},
            {"name": "send_email", "schema": {...}},
        ],
        "capabilities": ["search_web"],
        "memory": {"enabled": True, "provenance_tracking": False},
        "rate_limits": {"enabled": True},
        "circuit_breakers": {"enabled": False},
        "trust_config": {"ceiling": "STANDARD"},
        "supply_chain": {"hash_verification": False},
        "code_execution": {"enabled": False, "sandbox": False},
    }

Scan profiles
-------------
* ``standard``: All ten ASI categories.
* ``quick``: ASI-01, ASI-02, ASI-03 only.
* ``mcp_focused``: ASI-01, ASI-02, ASI-04, ASI-07.
* ``compliance``: All ten categories with stricter thresholds.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------


class ScanProfile(str, Enum):
    """Pre-defined scan profiles controlling which ASI categories to evaluate."""

    STANDARD = "standard"
    QUICK = "quick"
    MCP_FOCUSED = "mcp_focused"
    COMPLIANCE = "compliance"


_PROFILE_CATEGORIES: dict[ScanProfile, list[str]] = {
    ScanProfile.STANDARD: [
        "ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05",
        "ASI-06", "ASI-07", "ASI-08", "ASI-09", "ASI-10",
    ],
    ScanProfile.QUICK: ["ASI-01", "ASI-02", "ASI-03"],
    ScanProfile.MCP_FOCUSED: ["ASI-01", "ASI-02", "ASI-04", "ASI-07"],
    ScanProfile.COMPLIANCE: [
        "ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05",
        "ASI-06", "ASI-07", "ASI-08", "ASI-09", "ASI-10",
    ],
}

_ASI_NAMES: dict[str, str] = {
    "ASI-01": "Goal and Task Hijacking",
    "ASI-02": "Tool and Resource Misuse",
    "ASI-03": "Identity and Privilege Compromise",
    "ASI-04": "Supply Chain and Dependency Risks",
    "ASI-05": "Insecure Code Execution",
    "ASI-06": "Memory and Context Manipulation",
    "ASI-07": "Inter-Agent Trust Exploitation",
    "ASI-08": "Cascading and Recursive Failures",
    "ASI-09": "Context Trust Exploitation",
    "ASI-10": "Rogue and Emergent Agent Behaviors",
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CategoryResult:
    """Result for a single ASI category.

    Attributes
    ----------
    asi_id:
        Category identifier (e.g. ``"ASI-01"``).
    name:
        Human-readable category name.
    status:
        ``"PASS"``, ``"WARN"``, or ``"FAIL"``.
    score:
        Numeric score for this category (0-100).
    summary:
        One-sentence description of the finding.
    findings:
        List of detailed finding strings.
    recommendations:
        Actionable remediation steps.
    auto_fixable:
        Whether the issue can be resolved automatically (always False in
        the scanner — requires human action).
    """

    asi_id: str
    name: str
    status: str
    score: int
    summary: str
    findings: list[str]
    recommendations: list[str]
    auto_fixable: bool = False


@dataclass(frozen=True)
class ScanResult:
    """Aggregate result of a full agent scan.

    Attributes
    ----------
    agent_id:
        Identifier of the scanned agent.
    profile:
        The scan profile used.
    score:
        Overall security score (0-100), average of category scores.
    grade:
        Letter grade derived from score (A–F).
    category_results:
        Per-ASI-category results.
    scanned_at:
        UTC timestamp of the scan.
    scan_duration_ms:
        Wall-clock time for the scan in milliseconds.
    passed:
        Count of PASS categories.
    warned:
        Count of WARN categories.
    failed:
        Count of FAIL categories.
    """

    agent_id: str
    profile: str
    score: int
    grade: str
    category_results: list[CategoryResult]
    scanned_at: datetime
    scan_duration_ms: float
    passed: int
    warned: int
    failed: int


# ---------------------------------------------------------------------------
# Grade mapping
# ---------------------------------------------------------------------------


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Individual category check functions
# ---------------------------------------------------------------------------


def _check_asi01(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-01: Goal and Task Hijacking — check for boundary defense configuration."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    system_prompt = config.get("system_prompt", "")
    if not system_prompt:
        findings.append("No system prompt declared — boundary between instructions and data is undefined.")
        recommendations.append("Define an explicit system prompt that clearly separates agent instructions from user/data input.")
        score -= 30
    elif len(str(system_prompt)) < 50:
        findings.append("System prompt is very short — may not establish clear instruction-data boundaries.")
        recommendations.append("Expand the system prompt to include explicit data-plane handling instructions.")
        score -= 15

    input_validation = config.get("input_validation", {})
    if not input_validation or not isinstance(input_validation, dict):
        findings.append("No input validation configuration found — untrusted input may be processed without boundary checks.")
        recommendations.append("Enable input validation and configure BoundaryDetector for all external inputs.")
        score -= 25 if strict else 20

    if not config.get("input_sanitization"):
        findings.append("Input sanitisation not explicitly configured.")
        recommendations.append("Configure input sanitisation to strip Unicode control characters and structural delimiters.")
        score -= 15

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Instruction-data boundary defenses are adequately configured."
        if not findings
        else f"{len(findings)} boundary defense gap(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-01",
        name=_ASI_NAMES["ASI-01"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi02(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-02: Tool and Resource Misuse — check tool schema and rate limit config."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    tools = config.get("tools", [])
    if not isinstance(tools, list):
        tools = []

    if not tools:
        findings.append("No tools declared in agent configuration.")
        recommendations.append("Declare all tools the agent may invoke with their argument schemas.")
        score -= 20

    tools_without_schema: list[str] = []
    for tool in tools:
        if isinstance(tool, dict):
            tool_name = str(tool.get("name", "<unnamed>"))
            if not tool.get("schema"):
                tools_without_schema.append(tool_name)

    if tools_without_schema:
        findings.append(
            f"{len(tools_without_schema)} tool(s) lack argument schemas: "
            f"{tools_without_schema[:5]!r}"
        )
        recommendations.append(
            "Add ToolSchema declarations for every tool.  Use SchemaValidator to "
            "enforce argument types, ranges, and required fields at call time."
        )
        score -= min(40, len(tools_without_schema) * 10)

    rate_limits = config.get("rate_limits", {})
    if not rate_limits or not isinstance(rate_limits, dict) or not rate_limits.get("enabled"):
        findings.append("Per-tool rate limiting is not enabled.")
        recommendations.append("Configure a RateLimiter with per-tool capacity and refill rate limits.")
        score -= 25

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Tool schema validation and rate limiting are configured."
        if not findings
        else f"{len(findings)} tool misuse defense gap(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-02",
        name=_ASI_NAMES["ASI-02"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi03(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-03: Identity and Privilege Compromise — check capability declarations."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    capabilities = config.get("capabilities", [])
    tools = config.get("tools", [])
    if isinstance(tools, list) and isinstance(capabilities, list):
        declared_tool_names = {
            str(t.get("name", "")) for t in tools if isinstance(t, dict)
        }
        cap_set = set(str(c) for c in capabilities)
        undeclared = declared_tool_names - cap_set
        if undeclared:
            findings.append(
                f"{len(undeclared)} tool(s) are declared but not listed in capabilities: "
                f"{sorted(undeclared)[:5]!r}"
            )
            recommendations.append(
                "Declare all tool names in the capabilities list to enable "
                "CapabilityChecker enforcement."
            )
            score -= min(30, len(undeclared) * 10)

    if not capabilities:
        findings.append("No capabilities declared — privilege scope is unbounded.")
        recommendations.append(
            "Declare the explicit set of tools and permissions the agent is authorised "
            "to use.  Apply the principle of least privilege."
        )
        score -= 40

    if not config.get("identity_verification"):
        findings.append("Agent identity verification is not configured.")
        recommendations.append(
            "Configure an identity token or verifiable credential for the agent so "
            "that peer agents can verify its identity claims."
        )
        score -= 20 if strict else 15

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Agent capabilities are explicitly declared and bounded."
        if not findings
        else f"{len(findings)} identity/privilege gap(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-03",
        name=_ASI_NAMES["ASI-03"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi04(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-04: Supply Chain and Dependency Risks — check hash verification config."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    supply_chain = config.get("supply_chain", {})
    if not isinstance(supply_chain, dict) or not supply_chain:
        findings.append("No supply chain configuration declared.")
        recommendations.append(
            "Add a supply_chain config block with hash_verification enabled and "
            "an allowlist of trusted vendors."
        )
        score -= 40

    else:
        if not supply_chain.get("hash_verification"):
            findings.append("Tool hash verification is not enabled.")
            recommendations.append(
                "Enable hash verification and populate the VendorVerifier allowlist "
                "with expected SHA-256 digests for all plugins and tools."
            )
            score -= 35

        if not supply_chain.get("vendor_allowlist"):
            findings.append("No vendor allowlist configured.")
            recommendations.append(
                "Maintain an explicit allowlist of approved vendors and their "
                "cryptographic signatures."
            )
            score -= 20

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Supply chain hash verification is configured."
        if not findings
        else f"{len(findings)} supply chain risk(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-04",
        name=_ASI_NAMES["ASI-04"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi05(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-05: Insecure Code Execution — check sandbox and scope configuration."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    code_execution = config.get("code_execution", {})
    if not isinstance(code_execution, dict):
        code_execution = {}

    if not code_execution or not code_execution.get("enabled"):
        # Code execution disabled — best posture if agent doesn't need it.
        return CategoryResult(
            asi_id="ASI-05",
            name=_ASI_NAMES["ASI-05"],
            status="PASS",
            score=100,
            summary="Code execution is disabled — lowest risk posture.",
            findings=[],
            recommendations=[
                "If code execution is ever enabled, configure ScopeLimiter with "
                "explicit allowed_roots and allowed_commands."
            ],
        )

    if not code_execution.get("sandbox"):
        findings.append("Code execution is enabled but sandbox isolation is not configured.")
        recommendations.append(
            "Run code execution in an isolated sandbox (e.g., Docker, gVisor) "
            "with no network access and a restricted filesystem view."
        )
        score -= 40

    if not code_execution.get("allowed_paths"):
        findings.append("No file-path scope restrictions configured for code execution.")
        recommendations.append(
            "Configure ScopeLimiter with allowed_roots restricted to the agent's "
            "dedicated workspace directory."
        )
        score -= 25

    if not code_execution.get("command_allowlist"):
        findings.append("No command allowlist configured — all shell commands may be executable.")
        recommendations.append(
            "Define an explicit command allowlist in ScopeLimiter containing only "
            "the executables the agent legitimately needs."
        )
        score -= 25 if strict else 20

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Code execution scope restrictions are configured."
        if not findings
        else f"{len(findings)} code execution risk(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-05",
        name=_ASI_NAMES["ASI-05"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi06(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-06: Memory and Context Manipulation — check provenance tracking."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    memory = config.get("memory", {})
    if not isinstance(memory, dict):
        memory = {}

    if not memory or not memory.get("enabled"):
        return CategoryResult(
            asi_id="ASI-06",
            name=_ASI_NAMES["ASI-06"],
            status="PASS",
            score=100,
            summary="Persistent memory is disabled — no memory poisoning surface.",
            findings=[],
            recommendations=[
                "If memory is ever enabled, configure ProvenanceTracker and "
                "enforce trust-level checks before using retrieved memories."
            ],
        )

    if not memory.get("provenance_tracking"):
        findings.append("Persistent memory is enabled but provenance tracking is not configured.")
        recommendations.append(
            "Enable ProvenanceTracker to record the source and trust level of every "
            "item written to agent memory."
        )
        score -= 40

    if not memory.get("trust_level_enforcement"):
        findings.append("Trust-level enforcement on memory reads is not configured.")
        recommendations.append(
            "Use ProvenanceTracker.verify_chain() before using memory items in "
            "sensitive operations.  Reject items below the required trust threshold."
        )
        score -= 30

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Memory provenance tracking is configured."
        if not findings
        else f"{len(findings)} memory poisoning risk(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-06",
        name=_ASI_NAMES["ASI-06"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi07(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-07: Inter-Agent Trust Exploitation — check message validation."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    inter_agent = config.get("inter_agent", {})
    if not isinstance(inter_agent, dict):
        inter_agent = {}

    tools = config.get("tools", [])
    has_agent_tools = any(
        isinstance(t, dict) and "agent" in str(t.get("name", "")).lower()
        for t in (tools if isinstance(tools, list) else [])
    )

    if not inter_agent and not has_agent_tools:
        return CategoryResult(
            asi_id="ASI-07",
            name=_ASI_NAMES["ASI-07"],
            status="PASS",
            score=100,
            summary="No inter-agent communication configured — minimal attack surface.",
            findings=[],
            recommendations=[
                "If inter-agent messaging is ever enabled, configure MessageValidator "
                "with schema definitions and a sender trust registry."
            ],
        )

    if not inter_agent.get("message_validation"):
        findings.append("Inter-agent message validation is not enabled.")
        recommendations.append(
            "Configure MessageValidator with message schemas for every inter-agent "
            "message type and a sender trust level registry."
        )
        score -= 35

    if not inter_agent.get("replay_protection"):
        findings.append("Replay protection for inter-agent messages is not configured.")
        recommendations.append(
            "Enable correlation-ID replay protection in MessageValidator with an "
            "appropriate TTL."
        )
        score -= 25 if strict else 20

    if not inter_agent.get("sender_allowlist"):
        findings.append("No sender allowlist configured for inter-agent communication.")
        recommendations.append(
            "Maintain an explicit allowlist of permitted peer agent identifiers "
            "and their trust levels."
        )
        score -= 20

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Inter-agent message validation is configured."
        if not findings
        else f"{len(findings)} inter-agent trust risk(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-07",
        name=_ASI_NAMES["ASI-07"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi08(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-08: Cascading and Recursive Failures — check circuit breaker config."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    circuit_breakers = config.get("circuit_breakers", {})
    if not isinstance(circuit_breakers, dict):
        circuit_breakers = {}

    if not circuit_breakers or not circuit_breakers.get("enabled"):
        findings.append("Circuit breakers are not configured.")
        recommendations.append(
            "Wrap all outbound agent/tool calls in CircuitBreaker instances.  "
            "Configure failure thresholds and recovery timeouts per dependency."
        )
        score -= 40

    if not config.get("retry_policy"):
        findings.append("No retry policy configured — failed calls may be retried indefinitely.")
        recommendations.append(
            "Configure an explicit retry policy with maximum retry counts and "
            "exponential back-off.  Integrate with the circuit breaker to avoid "
            "retrying into an open circuit."
        )
        score -= 20

    if not config.get("timeout_policy"):
        findings.append("No timeout policy configured — hanging calls may block the agent indefinitely.")
        recommendations.append(
            "Set per-tool call timeouts.  Timeouts should be shorter than the "
            "circuit breaker recovery window."
        )
        score -= 20

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Circuit breakers and resilience policies are configured."
        if not findings
        else f"{len(findings)} cascading failure risk(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-08",
        name=_ASI_NAMES["ASI-08"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi09(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-09: Context Trust Exploitation — check trust tier configuration."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    trust_config = config.get("trust_config", {})
    if not isinstance(trust_config, dict):
        trust_config = {}

    if not trust_config:
        findings.append("No trust configuration declared.")
        recommendations.append(
            "Declare a trust_config block specifying the agent's trust ceiling, "
            "current tier, and delegation policy."
        )
        score -= 35

    else:
        if not trust_config.get("ceiling"):
            findings.append("No trust ceiling declared — agent may claim any trust level.")
            recommendations.append(
                "Set an explicit trust ceiling in TrustVerifier to bound the "
                "maximum privilege the agent may ever claim."
            )
            score -= 30

        if trust_config.get("allow_self_escalation"):
            findings.append("Self-escalation of trust level is enabled — this is a high-risk configuration.")
            recommendations.append(
                "Disable self-escalation.  Trust level changes must be initiated "
                "by a higher-trust orchestrator, not by the agent itself."
            )
            score -= 30

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Trust tier configuration is properly bounded."
        if not findings
        else f"{len(findings)} trust exploitation risk(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-09",
        name=_ASI_NAMES["ASI-09"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


def _check_asi10(config: dict[str, object], strict: bool) -> CategoryResult:
    """ASI-10: Rogue and Emergent Agent Behaviors — check behavioral monitoring."""
    findings: list[str] = []
    recommendations: list[str] = []
    score = 100

    monitoring = config.get("behavioral_monitoring", {})
    if not isinstance(monitoring, dict):
        monitoring = {}

    if not monitoring or not monitoring.get("enabled"):
        findings.append("Behavioral monitoring is not enabled.")
        recommendations.append(
            "Enable BaselineProfiler to record behavioral metrics (tool call "
            "frequency, prompt length, error rate) and DriftDetector to alert "
            "on significant deviations from the baseline."
        )
        score -= 45

    else:
        if not monitoring.get("baseline_established"):
            findings.append("Behavioral baseline has not been established.")
            recommendations.append(
                "Run the agent in a controlled environment to accumulate at least "
                "30 observations per metric before enabling drift detection."
            )
            score -= 20

        if not monitoring.get("drift_alerts"):
            findings.append("Drift alerting is not configured.")
            recommendations.append(
                "Configure DriftDetector with ALERT and CRITICAL thresholds and "
                "connect alerts to an incident management system."
            )
            score -= 20

    score = max(0, score)
    status = "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL")
    summary = (
        "Behavioral monitoring and drift detection are configured."
        if not findings
        else f"{len(findings)} rogue behavior risk(s) detected."
    )
    return CategoryResult(
        asi_id="ASI-10",
        name=_ASI_NAMES["ASI-10"],
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
    )


_CATEGORY_CHECKS: dict[str, object] = {
    "ASI-01": _check_asi01,
    "ASI-02": _check_asi02,
    "ASI-03": _check_asi03,
    "ASI-04": _check_asi04,
    "ASI-05": _check_asi05,
    "ASI-06": _check_asi06,
    "ASI-07": _check_asi07,
    "ASI-08": _check_asi08,
    "ASI-09": _check_asi09,
    "ASI-10": _check_asi10,
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class AgentScanner:
    """Runs ASI defense checks against an agent configuration dictionary.

    The scanner performs structural analysis of the config to identify
    missing or insufficient security controls.  It does not execute the
    agent.

    Parameters
    ----------
    profile:
        The scan profile determining which ASI categories to evaluate.
        Accepts a ``ScanProfile`` enum value or a profile name string.

    Example
    -------
    >>> config = {
    ...     "agent_id": "my-agent",
    ...     "system_prompt": "You are a helpful assistant.",
    ...     "tools": [{"name": "search", "schema": {"type": "object"}}],
    ...     "capabilities": ["search"],
    ...     "rate_limits": {"enabled": True},
    ... }
    >>> scanner = AgentScanner()
    >>> result = scanner.scan(config)
    >>> result.grade
    'C'
    """

    def __init__(self, profile: ScanProfile | str = ScanProfile.STANDARD) -> None:
        if isinstance(profile, str):
            try:
                self._profile = ScanProfile(profile)
            except ValueError:
                raise ValueError(
                    f"Unknown scan profile {profile!r}. "
                    f"Valid profiles: {[p.value for p in ScanProfile]!r}"
                )
        else:
            self._profile = profile

    def scan(self, agent_config: dict[str, object]) -> ScanResult:
        """Scan *agent_config* and return a ``ScanResult``.

        Parameters
        ----------
        agent_config:
            Dict describing the agent's declared configuration.  See
            module docstring for the full key reference.

        Returns
        -------
        ScanResult
        """
        start_ns = time.monotonic_ns()
        scanned_at = datetime.now(tz=timezone.utc)

        categories = _PROFILE_CATEGORIES[self._profile]
        strict = self._profile is ScanProfile.COMPLIANCE

        category_results: list[CategoryResult] = []
        for asi_id in categories:
            check_fn = _CATEGORY_CHECKS.get(asi_id)
            if check_fn is not None and callable(check_fn):
                result = check_fn(agent_config, strict)  # type: ignore[call-arg]
                category_results.append(result)

        agent_id = str(agent_config.get("agent_id", "unknown"))
        passed = sum(1 for r in category_results if r.status == "PASS")
        warned = sum(1 for r in category_results if r.status == "WARN")
        failed = sum(1 for r in category_results if r.status == "FAIL")

        overall_score = (
            round(sum(r.score for r in category_results) / len(category_results))
            if category_results
            else 0
        )
        grade = _score_to_grade(overall_score)

        elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000

        return ScanResult(
            agent_id=agent_id,
            profile=self._profile.value,
            score=overall_score,
            grade=grade,
            category_results=category_results,
            scanned_at=scanned_at,
            scan_duration_ms=elapsed_ms,
            passed=passed,
            warned=warned,
            failed=failed,
        )
