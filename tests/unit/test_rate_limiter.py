"""Tests for global rate limiter with adaptive backoff."""

import asyncio
import time

import pytest

from nightowl.utils.rate_limiter import RateLimiter, get_global_limiter, reset_global_limiter


@pytest.fixture(autouse=True)
def clean_global():
    reset_global_limiter()
    yield
    reset_global_limiter()


class TestTokenBucket:
    def test_burst_tokens_available_immediately(self):
        limiter = RateLimiter(rate=10, burst=5)
        start = time.monotonic()

        async def acquire_all():
            for _ in range(5):
                await limiter.acquire()
                limiter.release()

        asyncio.run(acquire_all())
        elapsed = time.monotonic() - start
        # 5 tokens should be available immediately from burst
        assert elapsed < 1.0

    def test_rate_limiting_after_burst(self):
        limiter = RateLimiter(rate=100, burst=2)

        async def acquire_many():
            for _ in range(5):
                await limiter.acquire()
                limiter.release()

        start = time.monotonic()
        asyncio.run(acquire_many())
        elapsed = time.monotonic() - start
        # After 2 burst tokens, should wait for refills
        assert elapsed > 0.01


class TestAdaptiveBackoff:
    def test_backoff_increases_on_rate_limit(self):
        limiter = RateLimiter(rate=100, burst=10)
        initial_backoff = limiter.current_backoff
        limiter.report_rate_limited()
        assert limiter.current_backoff > initial_backoff

    def test_backoff_decreases_on_success(self):
        limiter = RateLimiter(rate=100, burst=10)
        limiter.report_rate_limited()
        limiter.report_rate_limited()
        high_backoff = limiter.current_backoff
        limiter.report_success()
        limiter.report_success()
        assert limiter.current_backoff <= high_backoff

    def test_backoff_capped_at_max(self):
        limiter = RateLimiter(rate=100, burst=10)
        for _ in range(50):
            limiter.report_rate_limited()
        assert limiter.current_backoff <= limiter._max_backoff

    def test_error_increases_backoff_less_than_rate_limit(self):
        limiter1 = RateLimiter(rate=100, burst=10)
        limiter2 = RateLimiter(rate=100, burst=10)
        limiter1.report_rate_limited()
        limiter2.report_error()
        assert limiter1.current_backoff > limiter2.current_backoff


class TestGlobalLimiter:
    def test_global_limiter_is_singleton(self):
        l1 = get_global_limiter()
        l2 = get_global_limiter()
        assert l1 is l2

    def test_reset_creates_new_instance(self):
        l1 = get_global_limiter()
        reset_global_limiter()
        l2 = get_global_limiter()
        assert l1 is not l2


class TestConcurrencySemaphore:
    def test_semaphore_limits_concurrent_requests(self):
        limiter = RateLimiter(rate=1000, burst=100, max_concurrent=3)
        max_concurrent = 0
        current = 0
        lock = asyncio.Lock()

        async def worker():
            nonlocal max_concurrent, current
            await limiter.acquire()
            async with lock:
                current += 1
                max_concurrent = max(max_concurrent, current)
            await asyncio.sleep(0.05)
            async with lock:
                current -= 1
            limiter.release()

        async def run():
            tasks = [asyncio.create_task(worker()) for _ in range(10)]
            await asyncio.gather(*tasks)

        asyncio.run(run())
        assert max_concurrent <= 3
