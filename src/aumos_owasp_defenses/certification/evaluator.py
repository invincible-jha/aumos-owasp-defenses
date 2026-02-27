"""CertificationEvaluator — derive an OWASP ASI certification level from scan results.

The evaluator accepts the raw output from :class:`~aumos_owasp_defenses.scanner.AgentScanner`
(a dict or a :class:`~aumos_owasp_defenses.scanner.ScanResult`) and applies the
two-pass WARN/STRICT logic to determine which certification level is attained.

WARN pass criteria (per category)
    The scanner's status for the category is ``"PASS"`` or ``"WARN"``.
    This means simple checks pass — the category is not in outright failure.

STRICT pass criteria (per category)
    The scanner's status is ``"PASS"`` *and* the category score is at or
    above the STRICT threshold (80 out of 100).  This means all thorough
    checks pass with no material gap.

Usage
-----
>>> from aumos_owasp_defenses.scanner import AgentScanner
>>> from aumos_owasp_defenses.certification import CertificationEvaluator
>>> scanner = AgentScanner()
>>> scan = scanner.scan({"agent_id": "demo", "system_prompt": "Be helpful."})
>>> evaluator = CertificationEvaluator()
>>> cert = evaluator.evaluate_scan_result(scan)
>>> cert.level in ("none", "asi-basic", "asi-standard", "asi-advanced")
True
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aumos_owasp_defenses.certification.levels import (
    CertificationLevel,
    determine_level,
)

if TYPE_CHECKING:
    from aumos_owasp_defenses.scanner.agent_scanner import ScanResult


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CategoryCertResult:
    """Certification assessment for a single OWASP ASI category.

    Attributes
    ----------
    category:
        Human-readable category label, e.g. ``"ASI-01: Goal and Task Hijacking"``.
    warn_passed:
        ``True`` when the category is not in outright failure (PASS or WARN).
    strict_passed:
        ``True`` when the category scored 80+ with a PASS status.
    findings_count:
        Number of findings reported by the scanner for this category.
    details:
        One-line summary copied from the scanner's category result.
    """

    category: str
    warn_passed: bool
    strict_passed: bool
    findings_count: int
    details: str


@dataclass(frozen=True)
class CertificationResult:
    """Aggregate certification outcome for a scanned agent.

    Attributes
    ----------
    level:
        The highest :class:`~aumos_owasp_defenses.certification.levels.CertificationLevel`
        attained.
    categories_assessed:
        Total number of ASI categories included in the evaluation.
    warn_passed:
        How many categories passed at WARN level.
    strict_passed:
        How many categories passed at STRICT level.
    category_results:
        Per-category breakdown of pass/fail at both levels.
    timestamp:
        ISO-8601 UTC string at which evaluation ran.
    overall_score:
        Normalised score in the range ``[0.0, 1.0]``, computed as the
        weighted mean of WARN-pass ratio and STRICT-pass ratio.
    """

    level: CertificationLevel
    categories_assessed: int
    warn_passed: int
    strict_passed: int
    category_results: list[CategoryCertResult]
    timestamp: str
    overall_score: float


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


#: Minimum scanner score (out of 100) required for a category to satisfy
#: the STRICT-level pass criterion.
STRICT_SCORE_THRESHOLD: int = 80

#: The 10 OWASP Agentic Security Initiative category identifiers.
OWASP_ASI_CATEGORIES: list[str] = [
    "ASI-01: Goal and Task Hijacking",
    "ASI-02: Tool and Resource Misuse",
    "ASI-03: Identity and Privilege Compromise",
    "ASI-04: Supply Chain and Dependency Risks",
    "ASI-05: Insecure Code Execution",
    "ASI-06: Memory and Context Manipulation",
    "ASI-07: Inter-Agent Trust Exploitation",
    "ASI-08: Cascading and Recursive Failures",
    "ASI-09: Context Trust Exploitation",
    "ASI-10: Rogue and Emergent Agent Behaviors",
]


class CertificationEvaluator:
    """Evaluate an agent scan result and assign an OWASP ASI certification level.

    The evaluator is stateless; a single instance can be reused across
    multiple scan evaluations.

    Parameters
    ----------
    strict_score_threshold:
        The scanner score (0–100) a category must reach for its STRICT-level
        check to be considered passed.  Defaults to 80.

    Example
    -------
    >>> evaluator = CertificationEvaluator()
    >>> scan_result_dict = {
    ...     "category_results": [
    ...         {"asi_id": "ASI-01", "status": "PASS", "score": 95,
    ...          "summary": "OK", "findings": []},
    ...     ]
    ... }
    >>> cert = evaluator.evaluate(scan_result_dict)
    >>> cert.categories_assessed
    1
    """

    OWASP_ASI_CATEGORIES: list[str] = OWASP_ASI_CATEGORIES

    def __init__(self, strict_score_threshold: int = STRICT_SCORE_THRESHOLD) -> None:
        self._strict_threshold = strict_score_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, scan_results: dict[str, object]) -> CertificationResult:
        """Evaluate a raw scan-result dict and return a :class:`CertificationResult`.

        The expected dict shape is the serialised form of
        :class:`~aumos_owasp_defenses.scanner.ScanResult`:
        ``{"category_results": [{"asi_id": ..., "status": ..., "score": ...,
        "summary": ..., "findings": [...]}, ...]}``

        Parameters
        ----------
        scan_results:
            Dict representation of a scanner result.  At minimum it must
            contain a ``"category_results"`` list.

        Returns
        -------
        CertificationResult
        """
        raw_categories = scan_results.get("category_results", [])
        if not isinstance(raw_categories, list):
            raw_categories = []

        category_cert_results: list[CategoryCertResult] = []
        for raw in raw_categories:
            if not isinstance(raw, dict):
                continue
            category_cert_results.append(self._assess_category_dict(raw))

        return self._build_result(category_cert_results)

    def evaluate_scan_result(self, scan_result: ScanResult) -> CertificationResult:
        """Evaluate a typed :class:`~aumos_owasp_defenses.scanner.ScanResult`.

        Convenience wrapper that avoids manual dict conversion.

        Parameters
        ----------
        scan_result:
            A result object returned by :class:`~aumos_owasp_defenses.scanner.AgentScanner`.

        Returns
        -------
        CertificationResult
        """
        category_cert_results: list[CategoryCertResult] = []
        for cat in scan_result.category_results:
            category_cert_results.append(
                self._assess_category(
                    category=f"{cat.asi_id}: {cat.name}",
                    status=cat.status,
                    score=cat.score,
                    findings=cat.findings,
                    summary=cat.summary,
                )
            )
        return self._build_result(category_cert_results)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assess_category_dict(self, raw: dict[str, object]) -> CategoryCertResult:
        """Build a :class:`CategoryCertResult` from a raw category dict."""
        asi_id = str(raw.get("asi_id", ""))
        name = str(raw.get("name", ""))
        status = str(raw.get("status", "FAIL"))
        score = int(raw.get("score", 0))
        summary = str(raw.get("summary", ""))
        findings_raw = raw.get("findings", [])
        findings: list[str] = (
            list(findings_raw) if isinstance(findings_raw, list) else []
        )

        label = f"{asi_id}: {name}" if name else asi_id
        return self._assess_category(
            category=label,
            status=status,
            score=score,
            findings=findings,
            summary=summary,
        )

    def _assess_category(
        self,
        category: str,
        status: str,
        score: int,
        findings: list[str],
        summary: str,
    ) -> CategoryCertResult:
        """Determine WARN and STRICT pass status for a single category.

        Parameters
        ----------
        category:
            Display label for the category (e.g. ``"ASI-01: Goal and Task Hijacking"``).
        status:
            Scanner status string: ``"PASS"``, ``"WARN"``, or ``"FAIL"``.
        score:
            Numeric scanner score for this category (0–100).
        findings:
            List of finding strings from the scanner.
        summary:
            One-sentence scanner summary for this category.

        Returns
        -------
        CategoryCertResult
        """
        warn_passed = status in ("PASS", "WARN")
        strict_passed = status == "PASS" and score >= self._strict_threshold
        return CategoryCertResult(
            category=category,
            warn_passed=warn_passed,
            strict_passed=strict_passed,
            findings_count=len(findings),
            details=summary,
        )

    def _build_result(
        self, category_cert_results: list[CategoryCertResult]
    ) -> CertificationResult:
        """Aggregate per-category results into a :class:`CertificationResult`."""
        total = len(category_cert_results)
        warn_count = sum(1 for r in category_cert_results if r.warn_passed)
        strict_count = sum(1 for r in category_cert_results if r.strict_passed)

        level = determine_level(
            warn_passed=warn_count,
            strict_passed=strict_count,
        )

        overall_score = _compute_overall_score(
            warn_passed=warn_count,
            strict_passed=strict_count,
            total=total,
        )

        timestamp = datetime.now(tz=timezone.utc).isoformat()

        return CertificationResult(
            level=level,
            categories_assessed=total,
            warn_passed=warn_count,
            strict_passed=strict_count,
            category_results=category_cert_results,
            timestamp=timestamp,
            overall_score=overall_score,
        )


# ---------------------------------------------------------------------------
# Score computation helper
# ---------------------------------------------------------------------------


def _compute_overall_score(warn_passed: int, strict_passed: int, total: int) -> float:
    """Compute a normalised overall score in ``[0.0, 1.0]``.

    The score is the weighted mean of the WARN-pass ratio (weight 0.4) and
    the STRICT-pass ratio (weight 0.6), rewarding thorough compliance more
    than basic compliance.

    Parameters
    ----------
    warn_passed:
        Number of categories that passed at WARN level.
    strict_passed:
        Number of categories that passed at STRICT level.
    total:
        Total categories assessed.

    Returns
    -------
    float
        Value in the range ``[0.0, 1.0]``, rounded to four decimal places.
    """
    if total == 0:
        return 0.0
    warn_ratio = warn_passed / total
    strict_ratio = strict_passed / total
    score = warn_ratio * 0.4 + strict_ratio * 0.6
    return round(min(1.0, max(0.0, score)), 4)
