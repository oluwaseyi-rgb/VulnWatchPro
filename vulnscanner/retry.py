"""
Retry helper with exponential backoff and jitter. Deliberately small and
dependency-free rather than pulling in `tenacity` for one behaviour.
"""
from __future__ import annotations

import functools
import logging
import random
import time
from typing import Callable, Iterable, Type

logger = logging.getLogger("vulnscanner.retry")


def retry(
    max_retries: int = 3,
    backoff_factor: float = 0.5,
    exceptions: Iterable[Type[BaseException]] = (Exception,),
    should_retry_result: Callable[[object], bool] | None = None,
    on_retry: Callable[[int, BaseException | None, object], None] | None = None,
):
    """
    Decorator: retries the wrapped call up to `max_retries` times.

    backoff schedule: backoff_factor * (2 ** attempt) + random jitter(0, 0.25s)
    should_retry_result: optional predicate on the return value (e.g. HTTP 503)
    that triggers a retry even without an exception.
    """
    exceptions = tuple(exceptions)

    def decorator(fn: Callable):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    result = fn(*args, **kwargs)
                except exceptions as exc:  # noqa: PERF203
                    last_exc = exc
                    if attempt >= max_retries:
                        logger.debug("giving up after %d retries: %s", attempt, exc)
                        raise
                    if on_retry:
                        on_retry(attempt, exc, None)
                else:
                    if should_retry_result and should_retry_result(result) and attempt < max_retries:
                        if on_retry:
                            on_retry(attempt, None, result)
                    else:
                        return result

                sleep_for = backoff_factor * (2 ** attempt) + random.uniform(0, 0.25)
                logger.debug("retry %d/%d in %.2fs", attempt + 1, max_retries, sleep_for)
                time.sleep(sleep_for)
            if last_exc:
                raise last_exc
            return result  # last (failing) result if only should_retry_result triggered

        return wrapper

    return decorator
