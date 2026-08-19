import time

from vulnscanner.ratelimit import TokenBucket


def test_unlimited_never_blocks():
    bucket = TokenBucket(0)
    start = time.monotonic()
    for _ in range(50):
        bucket.acquire()
    assert time.monotonic() - start < 0.1


def test_rate_limit_enforced():
    bucket = TokenBucket(rate_per_sec=10, burst=1)
    start = time.monotonic()
    for _ in range(5):
        bucket.acquire()
    elapsed = time.monotonic() - start
    # 5 tokens at 10/sec with burst 1 should take roughly (5-1)/10 = 0.4s
    assert elapsed >= 0.3


def test_burst_allows_immediate_tokens():
    bucket = TokenBucket(rate_per_sec=5, burst=5)
    start = time.monotonic()
    for _ in range(5):
        bucket.acquire()
    assert time.monotonic() - start < 0.15
