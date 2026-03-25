"""Structured logging with Rich console output."""

import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logger(
    name: str = "nightowl",
    level: str = "INFO",
    log_file: str | None = None,
) -> logging.Logger:
    """Configure and return a logger with Rich console + optional file output."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        # Rich console handler
        rich_handler = RichHandler(
            console=console,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(rich_handler)

        # File handler
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
            )
            logger.addHandler(file_handler)

    return logger
