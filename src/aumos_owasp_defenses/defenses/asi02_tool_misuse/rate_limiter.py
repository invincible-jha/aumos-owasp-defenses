"""ASI-02: Tool and Resource Misuse — Per-Tool Rate Limiter.

Implements a thread-safe token-bucket rate limiter that enforces call-rate
limits on individual tool names.  This guards against both runaway agent
loops and deliberate resource-exhaustion attacks.

Algorithm
---------
Token bucket (also known as "leaky bucket as meter"):

* Each tool starts with a full bucket of ``capacity`` tokens.
* Tokens refill at ``refill_rate`` tokens per second, up to ``capacity``.
* Each tool call consumes one token.
* If no token is available the call is denied.

This algorithm tolerates short bursts up to ``capacity`` while enforcing
a sustained throughput ceiling of ``refill_rate`` calls per second.

Thread safety
-------------
A single ``threading.Lock`` per bucket ensures that check/consume operations
are atomic.  The implementation is suitable for multi-threaded agents but
does **not** support distributed rate limiting across multiple processes.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a ``RateLimiter.check()`` or ``consume()`` call.

    Attributes
    ----------
    allowed:
        ``True`` when the call is within the rate limit.
    tool_name:
        The tool being checked.
    tokens_remaining:
        Number of tokens available **after** this operation.
    retry_after_seconds:
        Estimated seconds until a token becomes available.
        Zero when ``allowed`` is ``True``.
    """

    allowed: bool
    tool_name: str
    tokens_remaining: float
    retry_after_seconds: float


# ---------------------------------------------------------------------------
# Internal bucket state
# ---------------------------------------------------------------------------


@dataclass
class _Bucket:
    """Mutable token-bucket state for a single tool."""

    capacity: float
    refill_rate: float           # tokens per second
    tokens: float
    last_refill_ts: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def _refill(self) -> None:
        """Add tokens accrued since last refill (must be called under lock)."""
        now = time.monotonic()
        elapsed = now - self.last_refill_ts
        accrued = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + accrued)
        self.last_refill_ts = now


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Per-tool token-bucket rate limiter.

    Parameters
    ----------
    default_capacity:
        Default bucket size (burst allowance) for tools that have not been
        individually configured.  Defaults to 10 tokens.
    default_refill_rate:
        Default refill speed in tokens per second.  Defaults to 1.0.

    Example
    -------
    >>> limiter = RateLimiter(default_capacity=5, default_refill_rate=2.0)
    >>> limiter.configure_tool("search_web", capacity=3, refill_rate=0.5)
    >>> result = limiter.consume("search_web")
    >>> result.allowed
    True
    """

    def __init__(
        self,
        default_capacity: float = 10.0,
        default_refill_rate: float = 1.0,
    ) -> None:
        self._default_capacity = default_capacity
        self._default_refill_rate = default_refill_rate
        self._buckets: dict[str, _Bucket] = {}
        self._global_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure_tool(
        self,
        tool_name: str,
        capacity: float,
        refill_rate: float,
    ) -> None:
        """Set custom rate-limit parameters for *tool_name*.

        Parameters
        ----------
        tool_name:
            The tool identifier — must match the name used in ``check()``
            and ``consume()``.
        capacity:
            Maximum number of tokens the bucket can hold (burst size).
        refill_rate:
            Tokens added per second.

        Notes
        -----
        Calling this method on a tool that already has a configured bucket
        resets the bucket to full capacity.
        """
        with self._global_lock:
            self._buckets[tool_name] = _Bucket(
                capacity=capacity,
                refill_rate=refill_rate,
                tokens=capacity,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_create_bucket(self, tool_name: str) -> _Bucket:
        """Return the bucket for *tool_name*, creating it with defaults if absent."""
        with self._global_lock:
            if tool_name not in self._buckets:
                self._buckets[tool_name] = _Bucket(
                    capacity=self._default_capacity,
                    refill_rate=self._default_refill_rate,
                    tokens=self._default_capacity,
                )
            return self._buckets[tool_name]

    def _build_result(
        self,
        tool_name: str,
        allowed: bool,
        bucket: _Bucket,
    ) -> RateLimitResult:
        """Construct a ``RateLimitResult`` (must be called while bucket lock is held)."""
        if allowed or bucket.refill_rate <= 0:
            retry_after = 0.0
        else:
            tokens_needed = 1.0 - bucket.tokens
            retry_after = max(0.0, tokens_needed / bucket.refill_rate)
        return RateLimitResult(
            allowed=allowed,
            tool_name=tool_name,
            tokens_remaining=max(0.0, bucket.tokens),
            retry_after_seconds=retry_after,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check(self, tool_name: str) -> RateLimitResult:
        """Check whether a call to *tool_name* would be permitted **without**
        consuming a token.

        Use this for advisory checks (e.g., to compute a ``Retry-After``
        header) without actually counting the call.

        Parameters
        ----------
        tool_name:
            The tool to check.

        Returns
        -------
        RateLimitResult
            ``allowed`` is ``True`` if at least one token is available.
        """
        bucket = self._get_or_create_bucket(tool_name)
        with bucket.lock:
            bucket._refill()
            allowed = bucket.tokens >= 1.0
            return self._build_result(tool_name, allowed, bucket)

    def consume(self, tool_name: str) -> RateLimitResult:
        """Attempt to consume one token for a call to *tool_name*.

        Parameters
        ----------
        tool_name:
            The tool being invoked.

        Returns
        -------
        RateLimitResult
            ``allowed`` is ``True`` and a token was consumed if at least one
            token was available.  ``allowed`` is ``False`` and no token is
            consumed if the bucket is empty.
        """
        bucket = self._get_or_create_bucket(tool_name)
        with bucket.lock:
            bucket._refill()
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return self._build_result(tool_name, True, bucket)
            else:
                return self._build_result(tool_name, False, bucket)

    def reset(self, tool_name: str) -> None:
        """Reset a tool's bucket to full capacity.

        This is intended for use in test environments or after a deliberate
        administrative action (e.g., operator resetting a blocked tool).

        Parameters
        ----------
        tool_name:
            The tool whose bucket should be reset.
        """
        bucket = self._get_or_create_bucket(tool_name)
        with bucket.lock:
            bucket.tokens = bucket.capacity
            bucket.last_refill_ts = time.monotonic()

    def bucket_status(self, tool_name: str) -> dict[str, float]:
        """Return a snapshot of the bucket state for *tool_name*.

        Returns
        -------
        dict[str, float]
            Keys: ``capacity``, ``tokens``, ``refill_rate``.
        """
        bucket = self._get_or_create_bucket(tool_name)
        with bucket.lock:
            bucket._refill()
            return {
                "capacity": bucket.capacity,
                "tokens": bucket.tokens,
                "refill_rate": bucket.refill_rate,
            }
