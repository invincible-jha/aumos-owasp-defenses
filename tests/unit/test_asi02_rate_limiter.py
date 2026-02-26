"""Unit tests for ASI-02: Tool and Resource Misuse — RateLimiter.

Tests cover:
- Token consumption within limits (allowed)
- Exhausted bucket denies calls
- Reset behaviour restores full capacity
- Custom tool configuration
- Advisory check() without consuming
- bucket_status() snapshot
- Retry-after calculation
- Default bucket creation on first access
"""
from __future__ import annotations

import threading
import time

import pytest

from aumos_owasp_defenses.defenses.asi02_tool_misuse.rate_limiter import (
    RateLimitResult,
    RateLimiter,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def limiter() -> RateLimiter:
    """Default limiter with capacity=5 for faster test exhaustion."""
    return RateLimiter(default_capacity=5.0, default_refill_rate=1.0)


@pytest.fixture()
def tiny_limiter() -> RateLimiter:
    """Limiter with capacity=1 for immediate exhaustion tests."""
    return RateLimiter(default_capacity=1.0, default_refill_rate=0.1)


# ---------------------------------------------------------------------------
# Positive tests — calls within the limit are allowed
# ---------------------------------------------------------------------------


class TestWithinLimitAllowed:
    def test_first_consume_is_allowed(self, limiter: RateLimiter) -> None:
        result = limiter.consume("search_web")
        assert result.allowed is True

    def test_consecutive_calls_within_capacity_allowed(self, limiter: RateLimiter) -> None:
        for _ in range(5):
            result = limiter.consume("search_web")
            assert result.allowed is True

    def test_tokens_remaining_decreases_with_each_consume(self, limiter: RateLimiter) -> None:
        prev_tokens = 5.0
        for _ in range(4):
            result = limiter.consume("search_web")
            assert result.tokens_remaining < prev_tokens
            prev_tokens = result.tokens_remaining

    def test_allowed_result_has_zero_retry_after(self, limiter: RateLimiter) -> None:
        result = limiter.consume("search_web")
        assert result.retry_after_seconds == 0.0

    def test_tool_name_reflected_in_result(self, limiter: RateLimiter) -> None:
        result = limiter.consume("my_custom_tool")
        assert result.tool_name == "my_custom_tool"

    def test_different_tools_have_independent_buckets(self, limiter: RateLimiter) -> None:
        for _ in range(5):
            limiter.consume("tool_a")
        # tool_b should still have full capacity.
        result = limiter.consume("tool_b")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Negative tests — exhausted bucket denies calls
# ---------------------------------------------------------------------------


class TestExhaustedBucketDenies:
    def test_call_after_exhaustion_is_denied(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("search_web")  # exhausts the one token
        result = tiny_limiter.consume("search_web")
        assert result.allowed is False

    def test_denied_result_has_nonzero_retry_after(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("search_web")
        result = tiny_limiter.consume("search_web")
        assert result.retry_after_seconds > 0.0

    def test_denied_result_tokens_remaining_is_zero(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("search_web")
        result = tiny_limiter.consume("search_web")
        assert result.tokens_remaining == 0.0

    def test_burst_followed_by_denial(self, limiter: RateLimiter) -> None:
        for _ in range(5):
            limiter.consume("burst_tool")
        result = limiter.consume("burst_tool")
        assert result.allowed is False

    def test_denied_does_not_consume_tokens(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("t")  # consume the only token
        r1 = tiny_limiter.consume("t")  # denied
        r2 = tiny_limiter.consume("t")  # still denied — no token was consumed by r1
        assert r1.allowed is False
        assert r2.allowed is False
        assert r1.tokens_remaining == r2.tokens_remaining


# ---------------------------------------------------------------------------
# Reset behaviour
# ---------------------------------------------------------------------------


class TestResetBehaviour:
    def test_reset_restores_full_capacity(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("tool")  # exhaust
        denied = tiny_limiter.consume("tool")
        assert denied.allowed is False

        tiny_limiter.reset("tool")
        result = tiny_limiter.consume("tool")
        assert result.allowed is True

    def test_reset_on_unknown_tool_creates_full_bucket(self, limiter: RateLimiter) -> None:
        limiter.reset("new_tool")
        result = limiter.consume("new_tool")
        assert result.allowed is True

    def test_reset_then_exhaust_then_deny(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("tool")
        tiny_limiter.reset("tool")
        tiny_limiter.consume("tool")
        result = tiny_limiter.consume("tool")
        assert result.allowed is False


# ---------------------------------------------------------------------------
# Custom tool configuration
# ---------------------------------------------------------------------------


class TestConfigureTool:
    def test_configure_tool_sets_capacity(self) -> None:
        limiter = RateLimiter(default_capacity=10.0)
        limiter.configure_tool("special_tool", capacity=2.0, refill_rate=0.5)
        results = [limiter.consume("special_tool") for _ in range(3)]
        assert results[0].allowed is True
        assert results[1].allowed is True
        assert results[2].allowed is False

    def test_configure_tool_resets_existing_bucket(self) -> None:
        limiter = RateLimiter(default_capacity=1.0, default_refill_rate=0.1)
        limiter.consume("tool")  # exhaust default
        limiter.configure_tool("tool", capacity=3.0, refill_rate=1.0)
        result = limiter.consume("tool")
        assert result.allowed is True

    def test_reconfigure_does_not_affect_other_tools(self) -> None:
        limiter = RateLimiter(default_capacity=5.0)
        limiter.configure_tool("tool_a", capacity=1.0, refill_rate=0.1)
        limiter.consume("tool_a")
        denied = limiter.consume("tool_a")
        assert denied.allowed is False

        result = limiter.consume("tool_b")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Advisory check() — does not consume tokens
# ---------------------------------------------------------------------------


class TestCheckDoesNotConsume:
    def test_check_returns_allowed_when_tokens_available(self, limiter: RateLimiter) -> None:
        result = limiter.check("my_tool")
        assert result.allowed is True

    def test_check_does_not_consume_token(self, tiny_limiter: RateLimiter) -> None:
        # check 3 times — should still have the token after.
        for _ in range(3):
            tiny_limiter.check("tool")
        consume_result = tiny_limiter.consume("tool")
        assert consume_result.allowed is True

    def test_check_after_exhaustion_returns_denied(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("tool")
        result = tiny_limiter.check("tool")
        assert result.allowed is False

    def test_check_denied_has_nonzero_retry_after(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("tool")
        result = tiny_limiter.check("tool")
        assert result.retry_after_seconds > 0.0


# ---------------------------------------------------------------------------
# bucket_status() snapshot
# ---------------------------------------------------------------------------


class TestBucketStatus:
    def test_status_reflects_full_capacity_initially(self, limiter: RateLimiter) -> None:
        status = limiter.bucket_status("new_tool")
        assert status["capacity"] == 5.0
        assert status["tokens"] == pytest.approx(5.0, abs=0.1)

    def test_status_reflects_consumed_tokens(self, limiter: RateLimiter) -> None:
        limiter.consume("tool")
        status = limiter.bucket_status("tool")
        assert status["tokens"] < 5.0

    def test_status_contains_refill_rate(self, limiter: RateLimiter) -> None:
        status = limiter.bucket_status("tool")
        assert "refill_rate" in status
        assert status["refill_rate"] == 1.0

    def test_status_contains_capacity(self, limiter: RateLimiter) -> None:
        status = limiter.bucket_status("tool")
        assert "capacity" in status


# ---------------------------------------------------------------------------
# Thread safety — basic smoke test
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_consume_does_not_allow_over_capacity(self) -> None:
        limiter = RateLimiter(default_capacity=5.0, default_refill_rate=0.0)
        allowed_count = 0
        lock = threading.Lock()

        def worker() -> None:
            nonlocal allowed_count
            result = limiter.consume("shared_tool")
            if result.allowed:
                with lock:
                    allowed_count += 1

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Only the first 5 should have been allowed.
        assert allowed_count <= 5


# ---------------------------------------------------------------------------
# Retry-after accuracy
# ---------------------------------------------------------------------------


class TestRetryAfterAccuracy:
    def test_retry_after_is_nonnegative(self, tiny_limiter: RateLimiter) -> None:
        tiny_limiter.consume("tool")
        result = tiny_limiter.consume("tool")
        assert result.retry_after_seconds >= 0.0

    def test_retry_after_is_calculated_from_refill_rate(self) -> None:
        # With refill_rate=2.0, one token takes 0.5 seconds to accrue.
        limiter = RateLimiter(default_capacity=1.0, default_refill_rate=2.0)
        limiter.consume("tool")
        result = limiter.consume("tool")
        # retry_after should be approximately 0.5s (tokens_needed/refill_rate = 1/2).
        assert result.retry_after_seconds == pytest.approx(0.5, abs=0.05)
