"""Live agent scanning against OWASP ASI categories with badge scoring.

This module provides :class:`OWASPBadgeScanner`, which analyses an agent
configuration dict against each of the ten OWASP Agentic Security Initiative
(ASI) categories and returns a :class:`BadgeScanReport` that can be used to
generate compliance badges.

The scanner wraps the existing :class:`~aumos_owasp_defenses.scanner.AgentScanner`
and :class:`~aumos_owasp_defenses.certification.CertificationEvaluator` to
produce a unified report suitable for badge rendering.

Category status mapping
-----------------------
``"protected"``
    The scanner assigned status ``"PASS"`` *and* the category score is >= 80.
    All defensive controls for this category are in place.

``"partial"``
    The scanner assigned status ``"PASS"`` or ``"WARN"`` but with a score
    below 80, or status ``"WARN"`` regardless of score.  Some controls are
    present but not comprehensive.

``"unprotected"``
    The scanner assigned status ``"FAIL"``.  Critical defenses are absent.

Overall level mapping
---------------------
``"gold"``     — 9–10 categories protected
``"silver"``   — 7–8 categories protected  (or 9–10 partial)
``"bronze"``   — 5–6 categories protected  (or 7–8 partial)
``"none"``     — fewer than 5 protected and fewer than 7 partial

Usage
-----
>>> scanner = OWASPBadgeScanner()
>>> report = scanner.scan({"agent_id": "my-agent", "system_prompt": "Be helpful."})
>>> report.overall_level in ("gold", "silver", "bronze", "none")
True
>>> 0.0 <= report.score <= 1.0
True
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from aumos_owasp_defenses.scanner.agent_scanner import (
    AgentScanner,
    ScanProfile,
)
from aumos_owasp_defenses.scanner.agent_scanner import (
    CategoryResult as _CategoryResult,
)


# ---------------------------------------------------------------------------
# Public data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanResult:
    """Result for a single OWASP ASI category in a badge scan.

    Attributes
    ----------
    category:
        OWASP ASI category identifier, e.g. ``"ASI-01"``.
    status:
        One of ``"protected"``, ``"partial"``, or ``"unprotected"``.
    defenses_found:
        Tuple of defense controls detected as being configured.
    recommendations:
        Tuple of actionable remediation steps for gaps found.
    """

    category: str
    status: str  # "protected", "partial", "unprotected"
    defenses_found: tuple[str, ...]
    recommendations: tuple[str, ...]


@dataclass(frozen=True)
class BadgeScanReport:
    """Aggregate report from a badge scan.

    Attributes
    ----------
    scan_id:
        Unique identifier for this scan run (UUID4 string).
    timestamp:
        UTC datetime at which the scan was performed.
    results:
        Per-category scan results as a frozen tuple.
    overall_level:
        Highest badge level attained: ``"gold"``, ``"silver"``,
        ``"bronze"``, or ``"none"``.
    score:
        Normalised aggregate compliance score in ``[0.0, 1.0]``.
    """

    scan_id: str
    timestamp: datetime
    results: tuple[ScanResult, ...]
    overall_level: str  # "gold", "silver", "bronze", "none"
    score: float  # 0.0 - 1.0

    @property
    def protected_count(self) -> int:
        """Number of categories with status ``"protected"``."""
        return sum(1 for r in self.results if r.status == "protected")

    @property
    def partial_count(self) -> int:
        """Number of categories with status ``"partial"``."""
        return sum(1 for r in self.results if r.status == "partial")

    @property
    def unprotected_count(self) -> int:
        """Number of categories with status ``"unprotected"``."""
        return sum(1 for r in self.results if r.status == "unprotected")


# ---------------------------------------------------------------------------
# Status classification threshold
# ---------------------------------------------------------------------------

#: Minimum scanner score (0–100) for a PASS-status category to be classified
#: as "protected" (rather than "partial").
_PROTECTED_SCORE_THRESHOLD: int = 80


# ---------------------------------------------------------------------------
# Level determination
# ---------------------------------------------------------------------------


def _determine_overall_level(protected: int, partial: int) -> str:
    """Derive the overall badge level from protected and partial counts.

    Parameters
    ----------
    protected:
        Number of categories with ``"protected"`` status.
    partial:
        Number of categories with ``"partial"`` status.

    Returns
    -------
    str
        One of ``"gold"``, ``"silver"``, ``"bronze"``, or ``"none"``.
    """
    if protected >= 9:
        return "gold"
    # Combined rule for silver only applies when protected is below the bronze
    # threshold (< 5); once protected >= 5 the agent qualifies for bronze and
    # the partial-count boost cannot elevate it further to silver.
    if protected >= 7 or (protected < 5 and (protected + partial) >= 9):
        return "silver"
    if protected >= 5 or (protected + partial) >= 7:
        return "bronze"
    return "none"


def _compute_score(results: tuple[ScanResult, ...]) -> float:
    """Compute a normalised score in ``[0.0, 1.0]`` from scan results.

    ``"protected"`` counts as 1.0, ``"partial"`` as 0.5,
    ``"unprotected"`` as 0.0.  The average is taken across all categories.

    Parameters
    ----------
    results:
        The per-category scan results.

    Returns
    -------
    float
        Score in ``[0.0, 1.0]``, rounded to four decimal places.
    """
    if not results:
        return 0.0
    weights = {"protected": 1.0, "partial": 0.5, "unprotected": 0.0}
    total = sum(weights.get(r.status, 0.0) for r in results)
    return round(min(1.0, max(0.0, total / len(results))), 4)


# ---------------------------------------------------------------------------
# Category status classifier
# ---------------------------------------------------------------------------


def _classify_category_result(cat: _CategoryResult) -> str:
    """Map a scanner :class:`CategoryResult` to a badge status string.

    Parameters
    ----------
    cat:
        A single-category result from the underlying AgentScanner.

    Returns
    -------
    str
        ``"protected"``, ``"partial"``, or ``"unprotected"``.
    """
    if cat.status == "PASS" and cat.score >= _PROTECTED_SCORE_THRESHOLD:
        return "protected"
    if cat.status in ("PASS", "WARN"):
        return "partial"
    return "unprotected"


def _extract_defenses_found(cat: _CategoryResult) -> tuple[str, ...]:
    """Derive the list of defenses found from the absence of findings.

    The scanner's ``findings`` list records *gaps*; its absence of a finding
    for a specific control implies the control is present.  We infer which
    controls are in place by examining what the scanner did *not* flag as
    missing.

    Parameters
    ----------
    cat:
        Scanner category result.

    Returns
    -------
    tuple[str, ...]
        Tuple of human-readable defense names that appear to be configured.
    """
    # Map of known gap keywords to the control they imply
    _gap_to_control: dict[str, str] = {
        "system prompt": "System prompt defined",
        "input validation": "Input validation configured",
        "input sanitisation": "Input sanitisation configured",
        "tool hash verification": "Tool hash verification enabled",
        "vendor allowlist": "Vendor allowlist configured",
        "supply chain": "Supply chain configuration present",
        "rate limit": "Per-tool rate limiting enabled",
        "tool(s) lack argument schema": "Tool argument schemas declared",
        "no tools declared": "Tool declarations present",
        "capabilities": "Capabilities declared (least-privilege)",
        "identity verification": "Agent identity verification configured",
        "circuit breaker": "Circuit breakers configured",
        "retry policy": "Retry policy configured",
        "timeout policy": "Timeout policy configured",
        "sandbox": "Code execution sandbox configured",
        "allowed_paths": "Filesystem scope restrictions configured",
        "command allowlist": "Command allowlist configured",
        "provenance tracking": "Provenance tracking enabled",
        "trust-level enforcement": "Trust-level enforcement on memory reads",
        "message validation": "Inter-agent message validation enabled",
        "replay protection": "Replay protection configured",
        "sender allowlist": "Sender allowlist configured",
        "trust configuration": "Trust configuration declared",
        "trust ceiling": "Trust ceiling configured",
        "self-escalation": "Self-escalation disabled",
        "behavioral monitoring": "Behavioral monitoring enabled",
        "baseline": "Behavioral baseline established",
        "drift alert": "Drift alerting configured",
    }

    # All possible controls for this category
    _all_controls: dict[str, list[str]] = {
        "ASI-01": [
            "System prompt defined",
            "Input validation configured",
            "Input sanitisation configured",
        ],
        "ASI-02": [
            "Tool argument schemas declared",
            "Tool declarations present",
            "Per-tool rate limiting enabled",
        ],
        "ASI-03": [
            "Capabilities declared (least-privilege)",
            "Agent identity verification configured",
        ],
        "ASI-04": [
            "Supply chain configuration present",
            "Tool hash verification enabled",
            "Vendor allowlist configured",
        ],
        "ASI-05": [
            "Code execution sandbox configured",
            "Filesystem scope restrictions configured",
            "Command allowlist configured",
        ],
        "ASI-06": [
            "Provenance tracking enabled",
            "Trust-level enforcement on memory reads",
        ],
        "ASI-07": [
            "Inter-agent message validation enabled",
            "Replay protection configured",
            "Sender allowlist configured",
        ],
        "ASI-08": [
            "Circuit breakers configured",
            "Retry policy configured",
            "Timeout policy configured",
        ],
        "ASI-09": [
            "Trust configuration declared",
            "Trust ceiling configured",
            "Self-escalation disabled",
        ],
        "ASI-10": [
            "Behavioral monitoring enabled",
            "Behavioral baseline established",
            "Drift alerting configured",
        ],
    }

    # Start with all possible controls for this category
    all_controls = set(_all_controls.get(cat.asi_id, []))
    # Remove controls implied by findings
    missing_controls: set[str] = set()
    for finding in cat.findings:
        finding_lower = finding.lower()
        for keyword, control in _gap_to_control.items():
            if keyword in finding_lower and control in all_controls:
                missing_controls.add(control)

    found = all_controls - missing_controls
    return tuple(sorted(found))


# ---------------------------------------------------------------------------
# OWASPBadgeScanner
# ---------------------------------------------------------------------------


class OWASPBadgeScanner:
    """Scans an agent configuration for OWASP ASI compliance and produces
    a :class:`BadgeScanReport` suitable for badge generation.

    This class orchestrates the underlying
    :class:`~aumos_owasp_defenses.scanner.AgentScanner` and maps its output
    to the three-level status scheme (``"protected"`` / ``"partial"`` /
    ``"unprotected"``) used for badge scoring.

    Parameters
    ----------
    profile:
        The scan profile controlling which ASI categories are evaluated.
        Accepts a :class:`~aumos_owasp_defenses.scanner.ScanProfile` enum
        value or its string equivalent.  Defaults to ``"standard"`` (all
        ten categories).

    Example
    -------
    >>> scanner = OWASPBadgeScanner()
    >>> config = {
    ...     "agent_id": "demo",
    ...     "system_prompt": "You are a helpful assistant.",
    ...     "tools": [{"name": "search", "schema": {"type": "object"}}],
    ...     "capabilities": ["search"],
    ...     "rate_limits": {"enabled": True},
    ... }
    >>> report = scanner.scan(config)
    >>> report.overall_level in ("gold", "silver", "bronze", "none")
    True
    """

    def __init__(
        self,
        profile: ScanProfile | str = ScanProfile.STANDARD,
    ) -> None:
        self._agent_scanner = AgentScanner(profile=profile)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, agent_config: dict[str, object]) -> BadgeScanReport:
        """Scan *agent_config* and return a :class:`BadgeScanReport`.

        Parameters
        ----------
        agent_config:
            Dict describing the agent's declared configuration.  See
            :mod:`aumos_owasp_defenses.scanner.agent_scanner` for the
            full key reference.

        Returns
        -------
        BadgeScanReport
            Immutable report with per-category status and an overall level.
        """
        raw_scan = self._agent_scanner.scan(agent_config)

        scan_results: list[ScanResult] = [
            self._check_category(cat.asi_id, cat)
            for cat in raw_scan.category_results
        ]

        results_tuple = tuple(scan_results)
        protected = sum(1 for r in results_tuple if r.status == "protected")
        partial = sum(1 for r in results_tuple if r.status == "partial")
        level = _determine_overall_level(protected, partial)
        score = _compute_score(results_tuple)

        return BadgeScanReport(
            scan_id=str(uuid.uuid4()),
            timestamp=raw_scan.scanned_at,
            results=results_tuple,
            overall_level=level,
            score=score,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_category(
        self,
        category: str,
        cat_result: _CategoryResult,
    ) -> ScanResult:
        """Translate a single scanner :class:`CategoryResult` to :class:`ScanResult`.

        Parameters
        ----------
        category:
            The ASI category identifier (e.g. ``"ASI-01"``).
        cat_result:
            The raw scanner result for the category.

        Returns
        -------
        ScanResult
        """
        status = _classify_category_result(cat_result)
        defenses_found = _extract_defenses_found(cat_result)
        recommendations = tuple(cat_result.recommendations)

        return ScanResult(
            category=category,
            status=status,
            defenses_found=defenses_found,
            recommendations=recommendations,
        )
