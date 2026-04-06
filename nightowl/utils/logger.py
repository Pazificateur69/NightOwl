"""Structured logging with Rich console output, JSON mode, and log rotation."""

import json
import logging
import logging.handlers
import sys
import uuid
from contextvars import ContextVar
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console()

# Request/scan correlation ID
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")


def set_correlation_id(cid: str | None = None) -> str:
    """Set a correlation ID for the current async context. Returns the ID."""
    cid = cid or uuid.uuid4().hex[:12]
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    return _correlation_id.get()


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for machine-parseable output."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "correlation_id": get_correlation_id(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


class CorrelationFormatter(logging.Formatter):
    """Standard formatter that includes correlation ID."""

    def format(self, record: logging.LogRecord) -> str:
        record.correlation_id = get_correlation_id()
        return super().format(record)


def setup_logger(
    name: str = "nightowl",
    level: str = "INFO",
    log_file: str | None = None,
    json_output: bool = False,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
) -> logging.Logger:
    """Configure and return a logger.

    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        json_output: Use JSON format for file output
        max_bytes: Max log file size before rotation
        backup_count: Number of rotated log files to keep
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        # Rich console handler (always human-readable)
        rich_handler = RichHandler(
            console=console,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(rich_handler)

        # File handler with rotation
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            if json_output:
                file_handler.setFormatter(JSONFormatter())
            else:
                file_handler.setFormatter(CorrelationFormatter(
                    "%(asctime)s | %(levelname)-8s | %(correlation_id)s | %(name)s | %(message)s"
                ))
            logger.addHandler(file_handler)

    return logger
