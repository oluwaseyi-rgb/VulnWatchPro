"""
Central logging configuration. One place to control format/level so every
module just does `logger = logging.getLogger(__name__)`.
"""
from __future__ import annotations

import logging
import sys


class _RedactingFilter(logging.Filter):
    """Strips obvious secrets (Authorization headers, tokens) from log lines."""

    SENSITIVE_KEYS = ("authorization", "password", "token", "cookie", "set-cookie")

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        lower = msg.lower()
        if any(k in lower for k in self.SENSITIVE_KEYS):
            record.msg = self._redact(msg)
            record.args = ()
        return True

    @classmethod
    def _redact(cls, msg: str) -> str:
        for key in cls.SENSITIVE_KEYS:
            idx = msg.lower().find(key)
            if idx != -1:
                # redact everything after the key on that "line segment"
                end = msg.find("\n", idx)
                end = end if end != -1 else len(msg)
                msg = msg[:idx] + f"{key}: ***REDACTED***" + msg[end:]
        return msg


def setup_logging(level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    logger = logging.getLogger("vulnscanner")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    console.addFilter(_RedactingFilter())
    logger.addHandler(console)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(fmt)
        file_handler.addFilter(_RedactingFilter())
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger
