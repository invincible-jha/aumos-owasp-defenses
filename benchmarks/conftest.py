"""Shared bootstrap for aumos-owasp-defenses benchmarks."""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent
_SRC = _REPO_ROOT / "src"
_BENCHMARKS = _REPO_ROOT / "benchmarks"

for _path in [str(_SRC), str(_BENCHMARKS)]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

from aumos_owasp_defenses.defenses.asi01_goal_hijack import BoundaryDetector, check_safe
from aumos_owasp_defenses.scanner.agent_scanner import AgentScanner, ScanProfile

__all__ = ["BoundaryDetector", "check_safe", "AgentScanner", "ScanProfile"]
