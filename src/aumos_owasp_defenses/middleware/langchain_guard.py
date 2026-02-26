"""LangChain framework guard for OWASP ASI defenses.

Provides ``protect()``, a convenience wrapper that integrates ``OWASPGuard``
with LangChain-style agents and chains.

LangChain integration approach
-------------------------------
LangChain agents are callable objects whose primary input is a dict
with a ``"input"`` key (or a plain string for ``AgentExecutor``).
The ``protect()`` function wraps any such callable and intercepts the
input before passing it to the underlying agent.

``SecurityConfig`` controls which ASI categories are active and the
violation policy (``on_violation``):

* ``"block"`` — raise ``SecurityViolationError`` before the agent runs.
* ``"warn"``  — log a warning and allow the call to proceed.
* ``"log"``   — record to the Python logger silently and proceed.

``SecurityViolationError``
    Exception raised in ``"block"`` mode when a high/critical violation
    is detected.  Carries the full ``GuardResult`` for caller inspection.

Note: LangChain is an optional dependency.  This module does **not**
import it at the top level; it is only referenced in type comments so
the library can be installed without LangChain.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from aumos_owasp_defenses.middleware.guard import (
    GuardResult,
    OWASPGuard,
    SecurityConfig,
    SecurityViolation,
)

logger = logging.getLogger(__name__)

AgentInput = TypeVar("AgentInput", str, dict[str, object])
AgentOutput = TypeVar("AgentOutput")


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class SecurityViolationError(RuntimeError):
    """Raised in ``"block"`` mode when a security violation is detected.

    Attributes
    ----------
    guard_result:
        The full ``GuardResult`` from the guard pass that triggered the error.
    """

    def __init__(self, guard_result: GuardResult) -> None:
        self.guard_result = guard_result
        violation_summaries = "; ".join(
            v.description[:80] for v in guard_result.violations[:3]
        )
        super().__init__(
            f"Security violations detected ({len(guard_result.violations)}): "
            f"{violation_summaries}"
        )


# ---------------------------------------------------------------------------
# LangChain-style SecurityConfig (extends the core config)
# ---------------------------------------------------------------------------


@dataclass
class LangChainSecurityConfig(SecurityConfig):
    """Extends ``SecurityConfig`` with LangChain-specific options.

    Attributes
    ----------
    on_violation:
        Action when a high/critical violation is detected.
        One of ``"block"``, ``"warn"``, ``"log"``.
    agent_id:
        Default agent identifier passed to the guard.
    """

    on_violation: str = "block"
    agent_id: str = "langchain-agent"


# ---------------------------------------------------------------------------
# protect() — convenience wrapper
# ---------------------------------------------------------------------------


def protect(
    agent: Callable[[AgentInput], AgentOutput],
    config: LangChainSecurityConfig | None = None,
    guard: OWASPGuard | None = None,
) -> Callable[[AgentInput], AgentOutput]:
    """Wrap a LangChain-style callable with OWASP ASI defenses.

    Parameters
    ----------
    agent:
        The agent or chain callable to protect.  Must accept a single
        argument that is either a ``str`` or a ``dict`` with an ``"input"``
        key.
    config:
        ``LangChainSecurityConfig`` controlling active defenses and the
        violation policy.  Uses safe defaults when ``None``.
    guard:
        Pre-configured ``OWASPGuard`` instance.  If ``None``, one is
        constructed from *config*.

    Returns
    -------
    Callable[[AgentInput], AgentOutput]
        A wrapped callable with the same signature as *agent*.

    Example
    -------
    >>> def my_agent(input_text: str) -> str:
    ...     return f"Response to: {input_text}"
    >>> safe_agent = protect(my_agent)
    >>> safe_agent("Tell me about Python.")
    'Response to: Tell me about Python.'
    """
    effective_config = config or LangChainSecurityConfig()
    effective_guard = guard or OWASPGuard(config=effective_config)

    def _wrapped(agent_input: AgentInput) -> AgentOutput:
        # Extract the text to analyse.
        if isinstance(agent_input, str):
            input_text = agent_input
        elif isinstance(agent_input, dict):
            input_text = str(agent_input.get("input", ""))
        else:
            input_text = str(agent_input)

        result: GuardResult = effective_guard.protect(
            input_text, agent_id=effective_config.agent_id
        )

        if not result.passed:
            policy = effective_config.on_violation
            if policy == "block":
                raise SecurityViolationError(result)
            elif policy == "warn":
                for violation in result.violations:
                    logger.warning(
                        "ASI violation [%s] %s: %s",
                        violation.severity,
                        violation.category,
                        violation.description[:120],
                    )
            else:
                # "log" mode
                logger.info(
                    "ASI violations detected (log mode): %d violation(s)",
                    len(result.violations),
                )

        return agent(agent_input)

    # Preserve the original callable's name and docstring.
    _wrapped.__name__ = getattr(agent, "__name__", "protected_agent")
    _wrapped.__doc__ = getattr(agent, "__doc__", "")
    return _wrapped  # type: ignore[return-value]
