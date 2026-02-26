"""ASI-05: Insecure Code Execution defenses.

Public surface
--------------
``ScopeLimiter``
    Enforces file-path and command-execution scope restrictions.
``PathCheckResult``
    Result of ``ScopeLimiter.check_path()``.
``CommandCheckResult``
    Result of ``ScopeLimiter.check_command()``.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi05_code_execution.scope_limiter import (
    CommandCheckResult,
    PathCheckResult,
    ScopeLimiter,
)

__all__ = [
    "CommandCheckResult",
    "PathCheckResult",
    "ScopeLimiter",
]
