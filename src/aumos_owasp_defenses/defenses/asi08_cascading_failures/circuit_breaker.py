"""ASI-08: Cascading and Recursive Failures — Circuit Breaker.

Implements the circuit breaker resilience pattern to prevent a single
failing agent or tool from cascading into a system-wide outage.

The circuit breaker models three states:

``CLOSED``
    Normal operation.  Calls are passed through.  Failures are counted
    against a threshold.

``OPEN``
    The failure threshold has been exceeded.  Calls are immediately
    rejected without executing, allowing the downstream service time to
    recover.  The breaker transitions to ``HALF_OPEN`` after a configurable
    ``recovery_timeout`` elapses.

``HALF_OPEN``
    A single probe call is permitted.  If it succeeds, the breaker resets
    to ``CLOSED``; if it fails, it returns to ``OPEN``.

Threat model
------------
* An adversarial prompt causes an agent to loop or recursively call
  itself or a downstream service, leading to resource exhaustion.
* A compromised dependency service returns errors that the agent retries
  indefinitely, amplifying load.
* Cascading timeout failures propagate through an agent pipeline,
  bringing the entire workflow to a halt.

Defense strategy
----------------
* Wrap every outbound agent/tool call in a circuit breaker.
* Configure per-service failure thresholds and recovery timeouts.
* Fail fast and return a structured error immediately when the breaker is
  open, rather than stacking up waiting threads.
"""
from __future__ import annotations

import logging
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

ReturnType = TypeVar("ReturnType")


# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------


class CircuitState(Enum):
    """States of the circuit breaker finite state machine."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class CircuitOpenError(RuntimeError):
    """Raised when a call is rejected because the circuit is OPEN.

    Attributes
    ----------
    name:
        Name of the circuit breaker that rejected the call.
    retry_after_seconds:
        Estimated seconds until the breaker transitions to HALF_OPEN.
    """

    def __init__(self, name: str, retry_after_seconds: float) -> None:
        self.name = name
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Circuit breaker {name!r} is OPEN. "
            f"Retry after approximately {retry_after_seconds:.1f}s."
        )


# ---------------------------------------------------------------------------
# Call result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallResult:
    """Outcome of a ``CircuitBreaker.call()`` attempt.

    Attributes
    ----------
    success:
        ``True`` when the wrapped callable completed without raising.
    state_after:
        Circuit state immediately after the call.
    failure_count:
        Cumulative consecutive failure count at the time of the call.
    error:
        The exception raised by the callable, or ``None`` on success.
    """

    success: bool
    state_after: CircuitState
    failure_count: int
    error: Exception | None


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """Circuit breaker for agent and tool calls.

    Parameters
    ----------
    name:
        Human-readable identifier for this breaker (used in logs and errors).
    failure_threshold:
        Number of consecutive failures before the circuit opens.
        Defaults to 5.
    recovery_timeout:
        Seconds to wait in OPEN state before transitioning to HALF_OPEN.
        Defaults to 60.
    success_threshold:
        Number of consecutive successes in HALF_OPEN required to close
        the circuit.  Defaults to 1.

    Example
    -------
    >>> import time
    >>> breaker = CircuitBreaker("llm-api", failure_threshold=3, recovery_timeout=5)
    >>> def flaky_call() -> str:
    ...     raise ConnectionError("timeout")
    >>> for _ in range(3):
    ...     try:
    ...         breaker.call(flaky_call)
    ...     except Exception:
    ...         pass
    >>> breaker.state
    <CircuitState.OPEN: 'OPEN'>
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        success_threshold: int = 1,
    ) -> None:
        self._name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._success_threshold = success_threshold

        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._success_count: int = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        """Human-readable identifier for this breaker."""
        return self._name

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state

    @property
    def failure_count(self) -> int:
        """Consecutive failure count."""
        with self._lock:
            return self._failure_count

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def _maybe_transition_to_half_open(self) -> None:
        """Transition OPEN → HALF_OPEN if the recovery timeout has elapsed.

        Must be called while ``self._lock`` is held.
        """
        if (
            self._state is CircuitState.OPEN
            and self._opened_at is not None
            and (time.monotonic() - self._opened_at) >= self._recovery_timeout
        ):
            self._state = CircuitState.HALF_OPEN
            self._success_count = 0
            logger.info("CircuitBreaker %r → HALF_OPEN (recovery timeout elapsed)", self._name)

    def _on_success(self) -> None:
        """Handle a successful call (must be called while lock is held)."""
        if self._state is CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self._success_threshold:
                self._reset()
                logger.info("CircuitBreaker %r → CLOSED (recovered)", self._name)
        elif self._state is CircuitState.CLOSED:
            self._failure_count = 0

    def _on_failure(self) -> None:
        """Handle a failed call (must be called while lock is held)."""
        self._failure_count += 1
        if self._state is CircuitState.HALF_OPEN:
            self._open_circuit()
            logger.warning(
                "CircuitBreaker %r → OPEN (probe failed in HALF_OPEN)", self._name
            )
        elif (
            self._state is CircuitState.CLOSED
            and self._failure_count >= self._failure_threshold
        ):
            self._open_circuit()
            logger.warning(
                "CircuitBreaker %r → OPEN (failure threshold %d reached)",
                self._name,
                self._failure_threshold,
            )

    def _open_circuit(self) -> None:
        """Transition to OPEN state (must be called while lock is held)."""
        self._state = CircuitState.OPEN
        self._opened_at = time.monotonic()

    def _reset(self) -> None:
        """Reset to CLOSED state (must be called while lock is held)."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._opened_at = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def call(self, func: Callable[[], ReturnType]) -> ReturnType:
        """Execute *func* under circuit-breaker control.

        Parameters
        ----------
        func:
            Zero-argument callable to execute.

        Returns
        -------
        ReturnType
            The return value of *func* on success.

        Raises
        ------
        CircuitOpenError
            When the circuit is OPEN and the call is rejected immediately.
        Exception
            Any exception raised by *func* is re-raised after recording
            the failure.
        """
        with self._lock:
            self._maybe_transition_to_half_open()

            if self._state is CircuitState.OPEN:
                elapsed = (
                    (time.monotonic() - self._opened_at)
                    if self._opened_at is not None
                    else 0.0
                )
                retry_after = max(0.0, self._recovery_timeout - elapsed)
                raise CircuitOpenError(self._name, retry_after)

        # Execute outside the lock to avoid holding it during potentially
        # long-running operations.
        try:
            result = func()
        except Exception as exc:
            with self._lock:
                self._on_failure()
                state_after = self._state
                failure_count = self._failure_count
            # Record the result but let the exception propagate.
            logger.debug(
                "CircuitBreaker %r recorded failure: %s", self._name, exc
            )
            # Re-raise after state update.
            raise

        with self._lock:
            self._on_success()
            state_after = self._state
            failure_count = self._failure_count

        return result

    def force_open(self) -> None:
        """Administratively open the circuit regardless of failure count.

        Useful for maintenance windows or when a dependency is known to
        be degraded.
        """
        with self._lock:
            self._open_circuit()
            logger.warning("CircuitBreaker %r force-opened by operator", self._name)

    def force_close(self) -> None:
        """Administratively reset the circuit to CLOSED.

        Useful after maintenance when operators confirm the dependency
        has recovered.
        """
        with self._lock:
            self._reset()
            logger.info("CircuitBreaker %r force-closed by operator", self._name)

    def get_status(self) -> dict[str, object]:
        """Return a status snapshot dict.

        Returns
        -------
        dict[str, object]
            Keys: ``name``, ``state``, ``failure_count``, ``success_count``,
            ``failure_threshold``, ``recovery_timeout``.
        """
        with self._lock:
            self._maybe_transition_to_half_open()
            return {
                "name": self._name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "failure_threshold": self._failure_threshold,
                "recovery_timeout": self._recovery_timeout,
            }
