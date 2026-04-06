"""Tests for config validation and schema."""

import pytest

from nightowl.config.schema import ConfigValidationError, validate_config
from nightowl.models.config import NightOwlConfig, RateLimitConfig, ScopeConfig


class TestValidateConfig:
    def test_valid_config_no_warnings(self):
        config = NightOwlConfig(
            mode="auto",
            db_path=":memory:",
            scope=ScopeConfig(allowed_hosts=["example.com"]),
        )
        warnings = validate_config(config)
        assert len(warnings) == 0

    def test_empty_scope_warns(self):
        config = NightOwlConfig(mode="auto", db_path=":memory:")
        warnings = validate_config(config)
        assert any("scope" in w.lower() for w in warnings)

    def test_high_rate_limit_warns(self):
        config = NightOwlConfig(
            mode="auto",
            db_path=":memory:",
            scope=ScopeConfig(allowed_hosts=["example.com"]),
            rate_limit=RateLimitConfig(requests_per_second=200),
        )
        warnings = validate_config(config)
        assert any("rate limit" in w.lower() for w in warnings)

    def test_high_threads_warns(self):
        config = NightOwlConfig(
            mode="auto",
            db_path=":memory:",
            scope=ScopeConfig(allowed_hosts=["example.com"]),
            threads=100,
        )
        warnings = validate_config(config)
        assert any("thread" in w.lower() for w in warnings)


class TestStrictMode:
    def test_empty_scope_raises_in_strict(self):
        config = NightOwlConfig(mode="auto", db_path=":memory:")
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_config(config, strict=True)
        assert "scope" in str(exc_info.value).lower()

    def test_valid_config_passes_strict(self):
        config = NightOwlConfig(
            mode="auto",
            db_path=":memory:",
            scope=ScopeConfig(allowed_hosts=["example.com"]),
        )
        warnings = validate_config(config, strict=True)
        assert len(warnings) == 0
