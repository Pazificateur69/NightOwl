"""Tests for CLI scope enforcement helpers."""

import click
import pytest

from nightowl.cli.main import _ensure_target_in_scope
from nightowl.models.config import NightOwlConfig, ScopeConfig


def test_cli_requires_explicit_scope():
    config = NightOwlConfig(scope=ScopeConfig())
    with pytest.raises(click.ClickException):
        _ensure_target_in_scope(config, "https://example.com")


def test_cli_helper_allows_existing_scope():
    config = NightOwlConfig(scope=ScopeConfig(allowed_hosts=["example.com"]))
    _ensure_target_in_scope(config, "https://example.com")
