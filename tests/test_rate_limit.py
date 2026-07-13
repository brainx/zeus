from __future__ import annotations

import math
import threading
import unittest
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from zeus.rate_limit import RateDecision, TokenBucket


class FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self._now = now

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds

    def set(self, now: float) -> None:
        self._now = now


def run_100_threads(call: Callable[[], RateDecision]) -> list[RateDecision]:
    barrier = threading.Barrier(100)

    def consume_together() -> RateDecision:
        barrier.wait(timeout=5)
        return call()

    with ThreadPoolExecutor(max_workers=100) as executor:
        return list(executor.map(lambda _index: consume_together(), range(100)))


class TokenBucketTests(unittest.TestCase):
    def test_bucket_exhaustion_and_refill_are_deterministic(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(rate_per_minute=60, burst=2, clock=clock)

        self.assertTrue(bucket.consume().allowed)
        self.assertTrue(bucket.consume().allowed)
        denied = bucket.consume()
        self.assertFalse(denied.allowed)
        self.assertEqual(1, denied.retry_after_seconds)

        clock.advance(1.0)
        self.assertTrue(bucket.consume().allowed)

    def test_retry_after_rounds_up_to_a_positive_whole_second(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(rate_per_minute=40, burst=1, clock=clock)

        self.assertEqual(RateDecision(True, 0), bucket.consume())
        self.assertEqual(RateDecision(False, 2), bucket.consume())

        clock.advance(0.75)
        self.assertEqual(RateDecision(False, 1), bucket.consume())

    def test_clock_moving_backwards_does_not_create_tokens(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(rate_per_minute=60, burst=1, clock=clock)
        self.assertTrue(bucket.consume().allowed)

        clock.advance(-10.0)
        self.assertFalse(bucket.consume().allowed)
        clock.advance(10.0)
        self.assertFalse(bucket.consume().allowed)

        clock.advance(1.0)
        self.assertTrue(bucket.consume().allowed)

    def test_initial_clock_reading_must_be_finite(self) -> None:
        for reading in (math.nan, math.inf, -math.inf):
            with self.subTest(reading=reading), self.assertRaises(ValueError):
                TokenBucket(rate_per_minute=60, burst=1, clock=FakeClock(reading))

    def test_non_finite_clock_reading_denies_without_mutating_bucket(self) -> None:
        for reading in (math.nan, math.inf, -math.inf):
            with self.subTest(reading=reading):
                clock = FakeClock(10.0)
                bucket = TokenBucket(rate_per_minute=60, burst=2, clock=clock)
                self.assertEqual(RateDecision(True, 0), bucket.consume())

                clock.set(reading)
                self.assertEqual(RateDecision(False, 1), bucket.consume())

                clock.set(10.5)
                self.assertEqual(RateDecision(True, 0), bucket.consume())
                self.assertEqual(RateDecision(False, 1), bucket.consume())
                clock.set(11.0)
                self.assertEqual(RateDecision(True, 0), bucket.consume())

    def test_rate_and_burst_must_be_positive_integers(self) -> None:
        clock = FakeClock()
        for name, rate, burst in (
            ("boolean rate", True, 1),
            ("floating-point rate", 1.5, 1),
            ("boolean burst", 1, True),
            ("floating-point burst", 1, 1.5),
        ):
            with self.subTest(name=name), self.assertRaises(TypeError):
                TokenBucket(rate_per_minute=rate, burst=burst, clock=clock)  # type: ignore[arg-type]

        for name, rate, burst in (
            ("zero rate", 0, 1),
            ("negative rate", -1, 1),
            ("zero burst", 1, 0),
            ("negative burst", 1, -1),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                TokenBucket(rate_per_minute=rate, burst=burst, clock=clock)

    def test_concurrent_callers_cannot_overdraw_burst(self) -> None:
        bucket = TokenBucket(rate_per_minute=60, burst=10, clock=FakeClock())

        decisions = run_100_threads(bucket.consume)

        self.assertEqual(10, sum(decision.allowed for decision in decisions))


if __name__ == "__main__":
    unittest.main()
