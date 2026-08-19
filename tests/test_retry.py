import pytest

from vulnscanner.retry import retry


def test_retries_until_success():
    calls = {"n": 0}

    @retry(max_retries=3, backoff_factor=0.01, exceptions=(ValueError,))
    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("boom")
        return "ok"

    assert flaky() == "ok"
    assert calls["n"] == 3


def test_raises_after_exhausting_retries():
    @retry(max_retries=2, backoff_factor=0.01, exceptions=(ValueError,))
    def always_fails():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        always_fails()


def test_should_retry_result_predicate():
    calls = {"n": 0}

    @retry(max_retries=3, backoff_factor=0.01, should_retry_result=lambda r: r == "retry-me")
    def sometimes_bad_result():
        calls["n"] += 1
        return "retry-me" if calls["n"] < 2 else "final"

    assert sometimes_bad_result() == "final"
    assert calls["n"] == 2


def test_no_retry_needed_returns_immediately():
    calls = {"n": 0}

    @retry(max_retries=5, backoff_factor=0.01)
    def works_first_try():
        calls["n"] += 1
        return 42

    assert works_first_try() == 42
    assert calls["n"] == 1
