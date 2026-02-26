"""ASI-08: Cascading and Recursive Failures defenses.

Public surface
--------------
``CircuitBreaker``
    Circuit breaker for agent and tool calls.
``CircuitState``
    Enum: CLOSED, OPEN, HALF_OPEN.
``CircuitOpenError``
    Raised when a call is rejected because the circuit is OPEN.
``CallResult``
    Describes the outcome of a circuit-breaker-protected call.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi08_cascading_failures.circuit_breaker import (
    CallResult,
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)

__all__ = [
    "CallResult",
    "CircuitBreaker",
    "CircuitOpenError",
    "CircuitState",
]
