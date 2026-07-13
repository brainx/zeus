from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after_seconds: int


class TokenBucket:
    def __init__(
        self,
        rate_per_minute: int,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(rate_per_minute) is not int:
            raise TypeError("rate_per_minute must be an integer")
        if type(burst) is not int:
            raise TypeError("burst must be an integer")
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        if burst <= 0:
            raise ValueError("burst must be positive")

        self._tokens_per_second = rate_per_minute / 60.0
        self._burst = float(burst)
        self._tokens = self._burst
        self._clock = clock
        initial_time = clock()
        if not math.isfinite(initial_time):
            raise ValueError("clock must return a finite value")
        self._updated_at = initial_time
        self._lock = threading.Lock()

    def consume(self) -> RateDecision:
        with self._lock:
            now = self._clock()
            if not math.isfinite(now):
                return RateDecision(False, 1)
            elapsed = max(0.0, now - self._updated_at)
            self._tokens = min(
                self._burst,
                self._tokens + elapsed * self._tokens_per_second,
            )
            self._updated_at = max(self._updated_at, now)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return RateDecision(True, 0)

            wait = math.ceil((1.0 - self._tokens) / self._tokens_per_second)
            return RateDecision(False, max(1, wait))
