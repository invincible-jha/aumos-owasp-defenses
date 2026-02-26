"""OWASP ASI Top 10 middleware layer.

Provides ``OWASPGuard``, a single orchestration class that runs input text
through all enabled defense modules in a configured sequence, plus
framework-specific adapters for LangChain, CrewAI, and generic decorators.

Public surface
--------------
``OWASPGuard``
    Main middleware guard that orchestrates all ASI defense checks.
``SecurityConfig``
    Configuration dataclass controlling which ASI categories are enabled.
``GuardResult``
    Result returned by ``OWASPGuard.protect()``.
``SecurityViolation``
    Exception-style value object describing a single security violation.
``protect``
    LangChain convenience decorator/function.
``CrewAIGuard``
    CrewAI task/agent guard using callback hooks.
``generic_guard``
    Decorator factory for guarding arbitrary Python functions.
"""
from __future__ import annotations

from aumos_owasp_defenses.middleware.guard import (
    GuardResult,
    OWASPGuard,
    SecurityConfig,
    SecurityViolation,
)
from aumos_owasp_defenses.middleware.langchain_guard import protect
from aumos_owasp_defenses.middleware.crewai_guard import CrewAIGuard
from aumos_owasp_defenses.middleware.generic_guard import generic_guard

__all__ = [
    "CrewAIGuard",
    "GuardResult",
    "OWASPGuard",
    "SecurityConfig",
    "SecurityViolation",
    "generic_guard",
    "protect",
]
