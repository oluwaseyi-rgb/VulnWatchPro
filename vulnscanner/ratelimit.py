"""
Thread-safe token-bucket rate limiter shared by every worker thread so the
scanner never exceeds a configured requests-per-second ceiling, regardless
of how many concurrent threads are hammering the target.
"""
from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int | None = None):
        """
        rate_per_sec: sustained requests/sec allowed. 0 or None disables limiting.
        burst: max tokens that can accumulate (defaults to rate, min 1).
        """
        self.rate = rate_per_sec or 0
        self.capacity = max(burst or (rate_per_sec or 1), 1)
        self.tokens = self.capacity
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()
        self.waits = 0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed > 0 and self.rate > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now

    def acquire(self) -> None:
        if self.rate <= 0:
            return  # unlimited
        while True:
            with self.lock:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                deficit = 1 - self.tokens
                sleep_for = deficit / self.rate
                self.waits += 1
            time.sleep(sleep_for)
