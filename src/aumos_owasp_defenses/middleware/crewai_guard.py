"""CrewAI framework guard for OWASP ASI defenses.

Provides ``CrewAIGuard``, which integrates with CrewAI's callback system
to intercept task inputs and outputs for security analysis.

CrewAI integration approach
----------------------------
CrewAI agents execute tasks through a ``Crew`` object.  Each task has
an associated description (the instruction given to the agent).  CrewAI
supports ``before_kickoff_callbacks`` and ``after_kickoff_callbacks`` at
the crew level, and ``step_callback`` at the agent level.

``CrewAIGuard`` exposes three hook methods that match the expected
callback signatures:

* ``before_task(task_description)`` — call before any task executes.
  Checks the task description for boundary violations (ASI-01).
* ``after_task(task_output)`` — call after a task completes.
  Checks the output for data-exfiltration patterns.
* ``step_callback(step_output)`` — call after each agent step.
  Lightweight check on step-level output text.

These methods can be used as direct callbacks or wrapped using
``as_before_kickoff()`` / ``as_step_callback()`` adapters.

Note: CrewAI is an optional dependency and is NOT imported at the top
level.  Only the callback signatures need to match CrewAI's expectations.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from collections.abc import Callable

from aumos_owasp_defenses.middleware.guard import (
    GuardResult,
    OWASPGuard,
    SecurityConfig,
    SecurityViolation,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CrewAI guard
# ---------------------------------------------------------------------------


@dataclass
class CrewAISecurityConfig(SecurityConfig):
    """Extends ``SecurityConfig`` with CrewAI-specific options.

    Attributes
    ----------
    on_violation:
        ``"block"``, ``"warn"``, or ``"log"``.
    crew_id:
        Human-readable identifier for the crew (used in log messages).
    check_task_output:
        Whether to run ASI-01 boundary checks on task output text as
        well as input.  Disabled by default since output may legitimately
        contain quoted external content.
    """

    on_violation: str = "warn"
    crew_id: str = "crewai-crew"
    check_task_output: bool = False


class CrewAIViolationError(RuntimeError):
    """Raised in ``"block"`` mode by a CrewAI guard hook.

    Attributes
    ----------
    guard_result:
        The ``GuardResult`` that triggered the block.
    hook_name:
        The hook (``"before_task"``, ``"after_task"``, or ``"step_callback"``)
        that detected the violation.
    """

    def __init__(self, guard_result: GuardResult, hook_name: str) -> None:
        self.guard_result = guard_result
        self.hook_name = hook_name
        super().__init__(
            f"CrewAI security violation in {hook_name!r}: "
            f"{len(guard_result.violations)} violation(s) detected."
        )


class CrewAIGuard:
    """OWASP ASI guard with CrewAI callback hook methods.

    Parameters
    ----------
    config:
        ``CrewAISecurityConfig`` controlling active defenses and policy.
    guard:
        Pre-configured ``OWASPGuard``.  If ``None``, one is constructed
        from *config*.

    Example
    -------
    >>> crewai_guard = CrewAIGuard()
    >>> crewai_guard.before_task("Research the latest Python 3.13 features.")
    >>> # No violation raised — task description is clean.

    To use with CrewAI:

    .. code-block:: python

        from crewai import Crew, Agent, Task

        security = CrewAIGuard()

        crew = Crew(
            agents=[...],
            tasks=[...],
            step_callback=security.step_callback,
        )
        crew.kickoff()
    """

    def __init__(
        self,
        config: CrewAISecurityConfig | None = None,
        guard: OWASPGuard | None = None,
    ) -> None:
        self._config = config or CrewAISecurityConfig()
        self._guard = guard or OWASPGuard(config=self._config)

    # ------------------------------------------------------------------
    # Hook methods
    # ------------------------------------------------------------------

    def before_task(self, task_description: str) -> GuardResult:
        """Check a task description before execution.

        Parameters
        ----------
        task_description:
            The instruction/description string for the task.

        Returns
        -------
        GuardResult
            The result of the guard check.

        Raises
        ------
        CrewAIViolationError
            In ``"block"`` mode when a high/critical violation is found.
        """
        result = self._guard.protect(
            task_description,
            agent_id=self._config.crew_id,
        )
        self._handle_result(result, "before_task")
        return result

    def after_task(self, task_output: str) -> GuardResult:
        """Check task output for boundary violations.

        Only active when ``config.check_task_output`` is ``True``.

        Parameters
        ----------
        task_output:
            The output text produced by the completed task.

        Returns
        -------
        GuardResult
        """
        if not self._config.check_task_output:
            return GuardResult(passed=True, violations=[], warnings=[], checks_run=[])

        result = self._guard.protect(
            task_output,
            agent_id=self._config.crew_id,
        )
        self._handle_result(result, "after_task")
        return result

    def step_callback(self, step_output: object) -> None:
        """Lightweight callback suitable for CrewAI's ``step_callback`` parameter.

        Attempts to extract a string representation from *step_output* and
        runs a boundary check.  Violations are logged or raise depending on
        the configured policy.

        Parameters
        ----------
        step_output:
            The output of a single agent step.  CrewAI passes this as a
            ``crewai.agents.output_parser.AgentAction`` or similar object.
            Only the string representation is analysed here.
        """
        text = str(step_output)
        result = self._guard.protect(text, agent_id=self._config.crew_id)
        if not result.passed:
            self._handle_result(result, "step_callback")

    # ------------------------------------------------------------------
    # Callback adapters
    # ------------------------------------------------------------------

    def as_before_kickoff(self) -> Callable[[dict[str, object]], None]:
        """Return a before_kickoff callback compatible with CrewAI Crew.

        Returns
        -------
        Callable
            A function accepting a CrewAI inputs dict.
        """
        def _hook(inputs: dict[str, object]) -> None:
            text = str(inputs.get("input", str(inputs)))
            result = self._guard.protect(text, agent_id=self._config.crew_id)
            self._handle_result(result, "before_kickoff")

        return _hook

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_result(self, result: GuardResult, hook_name: str) -> None:
        """Apply the configured violation policy to a ``GuardResult``."""
        if result.passed:
            return

        policy = self._config.on_violation

        if policy == "block":
            raise CrewAIViolationError(result, hook_name)
        elif policy == "warn":
            for violation in result.violations:
                logger.warning(
                    "CrewAI ASI violation [%s/%s] %s: %s",
                    hook_name,
                    violation.category,
                    violation.severity,
                    violation.description[:120],
                )
        else:
            logger.info(
                "CrewAI ASI violations (log mode) hook=%r count=%d",
                hook_name,
                len(result.violations),
            )
