"""Tests for Pydantic models."""

import pytest
from nightowl.models.finding import Finding, Severity, FindingSummary
from nightowl.models.target import Target, TargetType
from nightowl.models.scan import ScanSession, ScanStatus, ScanMode
from nightowl.models.config import NightOwlConfig


class TestFinding:
    def test_create_finding(self):
        f = Finding(title="Test", severity=Severity.HIGH)
        assert f.title == "Test"
        assert f.severity == Severity.HIGH
        assert f.id is not None

    def test_severity_color(self):
        f = Finding(title="Test", severity=Severity.CRITICAL)
        assert f.severity_color == "red"

    def test_finding_summary(self, sample_finding):
        summary = FindingSummary.from_finding(sample_finding)
        assert summary.title == sample_finding.title
        assert summary.severity == sample_finding.severity


class TestTarget:
    def test_ip_detection(self):
        t = Target(host="192.168.1.1")
        assert t.target_type == TargetType.IP

    def test_domain_detection(self):
        t = Target(host="example.com")
        assert t.target_type == TargetType.DOMAIN

    def test_url_detection(self):
        t = Target(host="https://example.com/path")
        assert t.target_type == TargetType.URL

    def test_network_detection(self):
        t = Target(host="192.168.1.0/24")
        assert t.target_type == TargetType.NETWORK

    def test_scope_check(self):
        t = Target(host="test.example.com")
        assert t.is_in_scope(["*.example.com"])
        assert not t.is_in_scope(["other.com"])


class TestScanSession:
    def test_lifecycle(self):
        s = ScanSession(name="test")
        assert s.status == ScanStatus.PENDING

        s.start()
        assert s.status == ScanStatus.RUNNING
        assert s.started_at is not None

        s.complete(findings_count=5)
        assert s.status == ScanStatus.COMPLETED
        assert s.findings_count == 5
        assert s.duration_seconds is not None


class TestConfig:
    def test_default_config(self):
        c = NightOwlConfig()
        assert c.mode == "semi"
        assert c.threads == 10

    def test_module_check(self):
        c = NightOwlConfig()
        assert c.is_module_enabled("sqli-scanner") is True
