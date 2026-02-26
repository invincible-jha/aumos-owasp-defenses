"""Scanner package — runs all ASI defense checks against an agent configuration.

Public surface
--------------
``AgentScanner``
    Runs all ten ASI defense checks against an agent config dict.
``ScanResult``
    Aggregate scan result with score and grade.
``CategoryResult``
    Per-ASI-category result within a ``ScanResult``.
``ReportGenerator``
    Produces HTML, JSON, and Markdown reports from ``ScanResult`` objects.
"""
from __future__ import annotations

from aumos_owasp_defenses.scanner.agent_scanner import (
    AgentScanner,
    CategoryResult,
    ScanResult,
)
from aumos_owasp_defenses.scanner.report_generator import ReportGenerator

__all__ = [
    "AgentScanner",
    "CategoryResult",
    "ReportGenerator",
    "ScanResult",
]
