"""Test configuration and fixtures."""

import pytest

from nightowl.models.config import NightOwlConfig
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target


@pytest.fixture
def sample_config():
    return NightOwlConfig(
        mode="auto",
        db_path=":memory:",
        log_level="DEBUG",
    )


@pytest.fixture
def sample_target():
    return Target(host="127.0.0.1", port=80)


@pytest.fixture
def sample_web_target():
    return Target(host="http://localhost:8080")


@pytest.fixture
def sample_finding():
    return Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="A test vulnerability",
        evidence="Test evidence",
        remediation="Fix the thing",
        category="test",
        module_name="test-module",
        target="127.0.0.1",
    )


@pytest.fixture
def sample_findings():
    return [
        Finding(title="Critical SQLi", severity=Severity.CRITICAL, cvss_score=9.8, target="example.com", module_name="sqli-scanner"),
        Finding(title="Missing HSTS", severity=Severity.MEDIUM, cvss_score=4.3, target="example.com", module_name="header-analyzer"),
        Finding(title="Open port 22", severity=Severity.INFO, cvss_score=0, target="example.com", module_name="port-scanner"),
    ]
