"""Token bucket rate limiter with global semaphore and adaptive backoff."""

import asyncio
import logging
import time

logger = logging.getLogger("nightowl")

# Global rate limiter instance shared across all modules
_global_limiter: "RateLimiter | None" = None


def get_global_limiter(rate: float = 10.0, burst: int = 20) -> "RateLimiter":
    """Get or create the global rate limiter instance."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter(rate=rate, burst=burst)
    return _global_limiter


def reset_global_limiter() -> None:
    """Reset the global limiter (for testing)."""
    global _global_limiter
    _global_limiter = None


class RateLimiter:
    """Async rate limiter using token bucket algorithm with adaptive backoff.

    Features:
    - Token bucket for smooth rate limiting
    - Global concurrency semaphore to limit parallel requests
    - Adaptive backoff on 429/timeout responses
    """

    def __init__(self, rate: float = 10.0, burst: int = 20, max_concurrent: int = 50):
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_concurrent)
        # Adaptive backoff state
        self._backoff_factor: float = 1.0
        self._max_backoff: float = 30.0
        self._consecutive_errors: int = 0

    async def acquire(self) -> None:
        """Acquire a rate limit token, waiting if necessary."""
        await self._semaphore.acquire()
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_refill = now

            if self._tokens < 1:
                wait_time = ((1 - self._tokens) / self.rate) * self._backoff_factor
                await asyncio.sleep(wait_time)
                self._tokens = 0
                self._last_refill = time.monotonic()
            else:
                self._tokens -= 1

            # Apply backoff delay if we've been getting errors
            if self._backoff_factor > 1.0:
                backoff_wait = min(0.5 * self._backoff_factor, self._max_backoff)
                await asyncio.sleep(backoff_wait)

    def release(self) -> None:
        """Release the concurrency semaphore after a request completes."""
        self._semaphore.release()

    def report_success(self) -> None:
        """Report a successful request — gradually reduce backoff."""
        self._consecutive_errors = max(0, self._consecutive_errors - 1)
        if self._consecutive_errors == 0:
            self._backoff_factor = max(1.0, self._backoff_factor * 0.8)

    def report_rate_limited(self) -> None:
        """Report a 429 or timeout — increase backoff."""
        self._consecutive_errors += 1
        self._backoff_factor = min(
            self._max_backoff,
            self._backoff_factor * (1.5 + 0.5 * min(self._consecutive_errors, 5)),
        )
        logger.warning(
            f"Rate limited — backoff factor now {self._backoff_factor:.1f}x "
            f"({self._consecutive_errors} consecutive errors)"
        )

    def report_error(self) -> None:
        """Report a generic error (connection refused, etc.)."""
        self._consecutive_errors += 1
        self._backoff_factor = min(
            self._max_backoff,
            self._backoff_factor * 1.2,
        )

    @property
    def current_backoff(self) -> float:
        return self._backoff_factor
