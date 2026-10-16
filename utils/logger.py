"""
Centralized logging configuration for Sentinel Vulnerability Scanner.

Provides rotating file logs (logs/sentinel.log) plus a console handler,
and a get_logger() factory so every module logs through the same
formatting and configured level.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from utils.config import config, PROJECT_ROOT

LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "sentinel.log"

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-24s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _level_from_name(name: str) -> int:
    return getattr(logging, name.upper(), logging.INFO)


def setup_logging() -> None:
    """Idempotently configure the root 'sentinel' logger hierarchy."""
    global _configured
    if _configured:
        return

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    level = _level_from_name(config.get("app.log_level", "INFO"))

    root = logging.getLogger("sentinel")
    root.setLevel(level)
    root.propagate = False

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    root.addHandler(file_handler)
    root.addHandler(console_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger, e.g. get_logger('scanner.ports')."""
    setup_logging()
    return logging.getLogger(f"sentinel.{name}")
