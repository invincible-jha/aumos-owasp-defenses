"""Generic function-wrapper guard using Python decorators.

Provides ``generic_guard``, a decorator factory that wraps any Python
callable and applies OWASP ASI defenses to its string arguments or
return value.

This guard is framework-agnostic and can be applied to:

* Tool functions called by the agent.
* Output post-processors.
* Any function whose inputs or outputs should be security-scanned.

Example
-------
>>> from aumos_owasp_defenses.middleware.generic_guard import generic_guard

>>> @generic_guard(check_args=True, check_return=False)
... def process_document(content: str) -> str:
...     return content.upper()

>>> process_document("Hello world")  # passes cleanly
'HELLO WORLD'
"""
from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import ParamSpec, TypeVar

from aumos_owasp_defenses.middleware.guard import (
    GuardResult,
    OWASPGuard,
    SecurityConfig,
    SecurityViolation,
)

logger = logging.getLogger(__name__)

P = ParamSpec("P")
R = TypeVar("R")


# ---------------------------------------------------------------------------
# Violation exception
# ---------------------------------------------------------------------------


class GenericGuardViolationError(RuntimeError):
    """Raised when ``generic_guard`` detects a blocking violation.

    Attributes
    ----------
    guard_result:
        The ``GuardResult`` that triggered the block.
    """

    def __init__(self, guard_result: GuardResult) -> None:
        self.guard_result = guard_result
        super().__init__(
            f"Security violation: {len(guard_result.violations)} violation(s) "
            "detected by generic_guard."
        )


# ---------------------------------------------------------------------------
# Decorator factory
# ---------------------------------------------------------------------------


def generic_guard(
    guard: OWASPGuard | None = None,
    config: SecurityConfig | None = None,
    check_args: bool = True,
    check_return: bool = False,
    on_violation: str = "block",
    agent_id: str = "generic",
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator factory that adds OWASP ASI defenses to any callable.

    Parameters
    ----------
    guard:
        Pre-configured ``OWASPGuard`` instance.  If ``None``, one is built
        from *config*.
    config:
        ``SecurityConfig`` to use when constructing the guard.  Ignored
        when *guard* is provided.
    check_args:
        When ``True``, scan all positional and keyword string arguments
        before the wrapped function is called.
    check_return:
        When ``True``, scan the string return value after the function
        returns.
    on_violation:
        Violation policy: ``"block"``, ``"warn"``, or ``"log"``.
    agent_id:
        Agent identifier passed to the guard (used in logs and drift
        detection if a profiler is configured).

    Returns
    -------
    Callable[[Callable[P, R]], Callable[P, R]]
        A decorator that wraps callables.

    Raises
    ------
    GenericGuardViolationError
        In ``"block"`` mode when a high/critical violation is detected.
    ValueError
        When *on_violation* is not a recognised policy name.

    Example
    -------
    >>> @generic_guard(check_args=True, on_violation="warn")
    ... def summarise(text: str) -> str:
    ...     return text[:100]
    """
    if on_violation not in ("block", "warn", "log"):
        raise ValueError(
            f"Unknown violation policy {on_violation!r}. "
            "Must be one of: 'block', 'warn', 'log'."
        )

    effective_guard = guard or OWASPGuard(config=config or SecurityConfig())

    def _decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def _wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # --- Check arguments ---
            if check_args:
                string_inputs: list[str] = []
                for arg in args:
                    if isinstance(arg, str):
                        string_inputs.append(arg)
                for value in kwargs.values():
                    if isinstance(value, str):
                        string_inputs.append(value)

                for text in string_inputs:
                    result = effective_guard.protect(text, agent_id=agent_id)
                    if not result.passed:
                        _apply_policy(result, on_violation, func.__name__, "input")

            # --- Call the wrapped function ---
            return_value: R = func(*args, **kwargs)

            # --- Check return value ---
            if check_return and isinstance(return_value, str):
                result = effective_guard.protect(return_value, agent_id=agent_id)
                if not result.passed:
                    _apply_policy(result, on_violation, func.__name__, "output")

            return return_value

        return _wrapper

    return _decorator


def _apply_policy(
    result: GuardResult,
    policy: str,
    func_name: str,
    direction: str,
) -> None:
    """Apply the violation policy given a failing ``GuardResult``."""
    if policy == "block":
        raise GenericGuardViolationError(result)
    elif policy == "warn":
        for violation in result.violations:
            logger.warning(
                "generic_guard [%s/%s] %s %s: %s",
                func_name,
                direction,
                violation.category,
                violation.severity,
                violation.description[:120],
            )
    else:
        logger.info(
            "generic_guard [%s/%s] %d violation(s) (log mode)",
            func_name,
            direction,
            len(result.violations),
        )
