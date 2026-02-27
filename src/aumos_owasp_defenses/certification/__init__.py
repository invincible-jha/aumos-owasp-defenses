"""OWASP ASI compliance certification package.

Provides three-tier certification evaluation (Basic, Standard, Advanced)
and SVG badge generation for OWASP Agentic Security Initiative compliance.

Public surface
--------------
:class:`CertificationLevel`
    Enumeration of certification levels: NONE, BASIC, STANDARD, ADVANCED.
:class:`CertificationResult`
    Aggregate certification outcome including level, category breakdown,
    overall score, and timestamp.
:class:`CategoryCertResult`
    Per-category WARN/STRICT pass assessment.
:class:`CertificationEvaluator`
    Evaluates a scanner result dict or :class:`~aumos_owasp_defenses.scanner.ScanResult`
    and returns a :class:`CertificationResult`.
:class:`BadgeGenerator`
    Generates shields.io-style SVG compliance badges.
:func:`determine_level`
    Pure function: maps (warn_passed, strict_passed) counts to a
    :class:`CertificationLevel`.
:func:`is_valid_svg`
    Lightweight structural check that an SVG string is well-formed.

Example
-------
>>> from aumos_owasp_defenses.scanner import AgentScanner
>>> from aumos_owasp_defenses.certification import (
...     CertificationEvaluator,
...     BadgeGenerator,
...     CertificationLevel,
... )
>>> scanner = AgentScanner()
>>> scan = scanner.scan({"agent_id": "demo"})
>>> evaluator = CertificationEvaluator()
>>> result = evaluator.evaluate_scan_result(scan)
>>> result.level in list(CertificationLevel)
True
>>> gen = BadgeGenerator()
>>> svg = gen.generate(result.level)
>>> svg.startswith("<svg")
True
"""
from __future__ import annotations

from aumos_owasp_defenses.certification.badge import BadgeGenerator, is_valid_svg
from aumos_owasp_defenses.certification.evaluator import (
    CategoryCertResult,
    CertificationEvaluator,
    CertificationResult,
    OWASP_ASI_CATEGORIES,
)
from aumos_owasp_defenses.certification.levels import (
    CertificationLevel,
    LevelThresholds,
    LEVEL_THRESHOLDS,
    determine_level,
)

__all__ = [
    # levels
    "CertificationLevel",
    "LevelThresholds",
    "LEVEL_THRESHOLDS",
    "determine_level",
    # evaluator
    "CategoryCertResult",
    "CertificationEvaluator",
    "CertificationResult",
    "OWASP_ASI_CATEGORIES",
    # badge
    "BadgeGenerator",
    "is_valid_svg",
]
