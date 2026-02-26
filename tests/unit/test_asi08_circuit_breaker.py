"""Tests for ASI-08 CircuitBreaker."""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from aumos_owasp_defenses.defenses.asi08_cascading_failures.circuit_breaker import (
    CallResult,
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)


# ---------------------------------------------------------------------------
# CircuitOpenError
# ---------------------------------------------------------------------------


class TestCircuitOpenError:
    def test_attributes(self) -> None:
        err = CircuitOpenError("my-breaker", 30.5)
        assert err.name == "my-breaker"
        assert err.retry_after_seconds == 30.5
        assert "my-breaker" in str(err)
        assert "30.5" in str(err)

    def test_is_runtime_error(self) -> None:
        assert issubclass(CircuitOpenError, RuntimeError)


# ---------------------------------------------------------------------------
# CircuitBreaker — construction and properties
# ---------------------------------------------------------------------------


class TestCircuitBreakerConstruction:
    def test_initial_state_closed(self) -> None:
        breaker = CircuitBreaker("svc")
        assert breaker.state == CircuitState.CLOSED

    def test_name_property(self) -> None:
        breaker = CircuitBreaker("my-service")
        assert breaker.name == "my-service"

    def test_failure_count_initially_zero(self) -> None:
        breaker = CircuitBreaker("svc")
        assert breaker.failure_count == 0


# ---------------------------------------------------------------------------
# CircuitBreaker — closed state (normal operation)
# ---------------------------------------------------------------------------


class TestClosedState:
    def test_successful_call_returns_value(self) -> None:
        breaker = CircuitBreaker("svc")
        result = breaker.call(lambda: 42)
        assert result == 42

    def test_failure_increments_count(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=5)
        with pytest.raises(ValueError):
            breaker.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert breaker.failure_count == 1

    def test_success_resets_failure_count(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=5)
        for _ in range(3):
            try:
                breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
            except RuntimeError:
                pass
        breaker.call(lambda: "ok")
        assert breaker.failure_count == 0

    def test_threshold_reached_opens_circuit(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=3)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        assert breaker.state == CircuitState.OPEN

    def test_exception_propagates(self) -> None:
        breaker = CircuitBreaker("svc")
        with pytest.raises(ValueError, match="specific error"):
            breaker.call(lambda: (_ for _ in ()).throw(ValueError("specific error")))


# ---------------------------------------------------------------------------
# CircuitBreaker — open state
# ---------------------------------------------------------------------------


class TestOpenState:
    def test_call_raises_circuit_open_error(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1)
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        assert breaker.state == CircuitState.OPEN
        with pytest.raises(CircuitOpenError) as exc_info:
            breaker.call(lambda: "should not execute")
        assert exc_info.value.name == "svc"

    def test_force_open(self) -> None:
        breaker = CircuitBreaker("svc")
        breaker.force_open()
        assert breaker.state == CircuitState.OPEN

    def test_retry_after_is_non_negative(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=60)
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        with pytest.raises(CircuitOpenError) as exc_info:
            breaker.call(lambda: None)
        assert exc_info.value.retry_after_seconds >= 0


# ---------------------------------------------------------------------------
# CircuitBreaker — half-open state
# ---------------------------------------------------------------------------


class TestHalfOpenState:
    def test_transitions_to_half_open_after_timeout(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=0.05)
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        time.sleep(0.1)
        assert breaker.state == CircuitState.HALF_OPEN

    def test_successful_probe_closes_circuit(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=0.05)
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        time.sleep(0.1)
        breaker.call(lambda: "probe")
        assert breaker.state == CircuitState.CLOSED

    def test_failed_probe_reopens_circuit(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=0.05)
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        time.sleep(0.1)
        assert breaker.state == CircuitState.HALF_OPEN
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("probe fail")))
        assert breaker.state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# CircuitBreaker — force operations and get_status
# ---------------------------------------------------------------------------


class TestForceAndStatus:
    def test_force_close_resets_state(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1)
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        breaker.force_close()
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0

    def test_get_status_returns_dict(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=5, recovery_timeout=30)
        status = breaker.get_status()
        assert status["name"] == "svc"
        assert status["state"] == "CLOSED"
        assert status["failure_count"] == 0
        assert status["failure_threshold"] == 5
        assert status["recovery_timeout"] == 30

    def test_get_status_after_failure(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=5)
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        status = breaker.get_status()
        assert status["failure_count"] == 1

    def test_get_status_when_open(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1)
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        status = breaker.get_status()
        assert status["state"] == "OPEN"


# ---------------------------------------------------------------------------
# CircuitBreaker — success_threshold > 1
# ---------------------------------------------------------------------------


class TestSuccessThreshold:
    def test_multiple_successes_required_to_close(self) -> None:
        breaker = CircuitBreaker(
            "svc", failure_threshold=1, recovery_timeout=0.05, success_threshold=2
        )
        with pytest.raises(RuntimeError):
            breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        time.sleep(0.1)
        # First probe — should stay HALF_OPEN
        breaker.call(lambda: "probe1")
        assert breaker.state == CircuitState.HALF_OPEN
        # Second probe — should close
        breaker.call(lambda: "probe2")
        assert breaker.state == CircuitState.CLOSED
