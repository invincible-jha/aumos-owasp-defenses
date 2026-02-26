"""ASI-02: Tool and Resource Misuse defenses.

Public surface
--------------
``SchemaValidator``
    Validates tool-call arguments against declared ``ToolSchema`` specs.
``ToolSchema``
    Declares the argument contract for a single tool.
``ParameterSpec``
    Specification for one parameter within a ``ToolSchema``.
``ValidationResult``
    Result object returned by ``SchemaValidator.validate()``.
``SchemaViolation``
    A single constraint violation within a ``ValidationResult``.
``RateLimiter``
    Token-bucket rate limiter, one bucket per tool name.
``RateLimitResult``
    Result object returned by ``RateLimiter.check()`` / ``consume()``.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi02_tool_misuse.rate_limiter import (
    RateLimitResult,
    RateLimiter,
)
from aumos_owasp_defenses.defenses.asi02_tool_misuse.schema_validator import (
    ParameterSpec,
    SchemaViolation,
    SchemaValidator,
    ToolSchema,
    ValidationResult,
)

__all__ = [
    "ParameterSpec",
    "RateLimitResult",
    "RateLimiter",
    "SchemaViolation",
    "SchemaValidator",
    "ToolSchema",
    "ValidationResult",
]
