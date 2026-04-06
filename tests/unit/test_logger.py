"""Tests for structured logging system."""

import json
import logging

import pytest

from nightowl.utils.logger import (
    JSONFormatter,
    get_correlation_id,
    set_correlation_id,
    setup_logger,
)


class TestCorrelationId:
    def test_default_is_dash(self):
        assert get_correlation_id() == "-"

    def test_set_and_get(self):
        cid = set_correlation_id("test-123")
        assert cid == "test-123"
        assert get_correlation_id() == "test-123"

    def test_auto_generate(self):
        cid = set_correlation_id()
        assert len(cid) == 12
        assert cid != "-"


class TestJSONFormatter:
    def test_formats_as_valid_json(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="nightowl",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["msg"] == "Test message"
        assert "ts" in parsed
        assert "correlation_id" in parsed

    def test_includes_exception(self):
        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="nightowl",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Caught error",
                args=None,
                exc_info=sys.exc_info(),
            )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]


class TestSetupLogger:
    def test_creates_logger_with_handlers(self):
        # Use a unique name to avoid handler conflicts
        logger = setup_logger(name="test-setup-unique", level="DEBUG")
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) >= 1

    def test_file_handler_with_rotation(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = setup_logger(
            name="test-file-unique",
            level="INFO",
            log_file=log_file,
        )
        logger.info("Test message")
        with open(log_file) as f:
            content = f.read()
        assert "Test message" in content

    def test_json_file_handler(self, tmp_path):
        log_file = str(tmp_path / "test.json.log")
        logger = setup_logger(
            name="test-json-unique",
            level="INFO",
            log_file=log_file,
            json_output=True,
        )
        logger.info("JSON test")
        with open(log_file) as f:
            line = f.readline().strip()
        parsed = json.loads(line)
        assert parsed["msg"] == "JSON test"
