"""Tests for the database layer."""

import asyncio

import pytest

from nightowl.db.database import Database
from nightowl.models.finding import Finding, Severity
from nightowl.models.scan import ScanSession, ScanMode


@pytest.fixture
def db():
    """Create an in-memory database for testing."""
    database = Database(db_path=":memory:")
    asyncio.run(database.init())
    return database


class TestDatabase:
    def test_init(self, db):
        assert db.engine is not None
        assert db._session_factory is not None

    def test_save_and_get_scan(self, db):
        session = ScanSession(name="test-scan", mode=ScanMode.AUTO)
        session.start()
        session.complete(findings_count=2)

        findings = [
            Finding(title="Finding 1", severity=Severity.HIGH, target="127.0.0.1"),
            Finding(title="Finding 2", severity=Severity.LOW, target="127.0.0.1"),
        ]

        asyncio.run(db.save_scan(session, findings))
        scans = asyncio.run(db.get_scans())
        assert len(scans) == 1
        assert scans[0]["name"] == "test-scan"
        assert scans[0]["findings_count"] == 2

    def test_get_findings(self, db):
        session = ScanSession(name="test-scan")
        session.start()
        findings = [
            Finding(
                title="SQLi",
                severity=Severity.CRITICAL,
                target="x.com",
                module_name="sqli",
                confidence_score=0.91,
            ),
        ]
        asyncio.run(db.save_scan(session, findings))

        result = asyncio.run(db.get_findings(session.id))
        assert len(result) == 1
        assert result[0]["title"] == "SQLi"
        assert result[0]["severity"] == "critical"
        assert result[0]["confidence_score"] == 0.91
        assert result[0]["finding_state"] == "info"

    def test_finding_stats(self, db):
        session = ScanSession(name="test-scan")
        session.start()
        findings = [
            Finding(title="A", severity=Severity.CRITICAL),
            Finding(title="B", severity=Severity.HIGH),
            Finding(title="C", severity=Severity.HIGH),
            Finding(title="D", severity=Severity.MEDIUM),
            Finding(title="E", severity=Severity.INFO),
        ]
        asyncio.run(db.save_scan(session, findings))

        stats = asyncio.run(db.get_finding_stats(session.id))
        assert stats["critical"] == 1
        assert stats["high"] == 2
        assert stats["medium"] == 1
        assert stats["info"] == 1

    def test_upsert_scan(self, db):
        """Saving a scan with the same ID should update, not duplicate."""
        session = ScanSession(name="initial")
        session.start()
        asyncio.run(db.save_scan(session, []))

        # Now update with findings
        session.complete(findings_count=1)
        findings = [Finding(title="Late finding", severity=Severity.HIGH)]
        asyncio.run(db.save_scan(session, findings))

        scans = asyncio.run(db.get_scans())
        assert len(scans) == 1
        assert scans[0]["status"] == "completed"
        assert scans[0]["findings_count"] == 1
        assert scans[0]["name"] == "initial"

    def test_error_persistence(self, db):
        session = ScanSession(name="errored-scan")
        session.start()
        errors = [
            {"module": "sqli-scanner", "target": "x.com", "stage": "scan", "error": "Timeout"},
            {"module": "xss-scanner", "target": "x.com", "stage": "scan", "error": "Connection refused"},
        ]
        asyncio.run(db.save_scan(session, [], errors=errors))

        result = asyncio.run(db.get_scan_errors(session.id))
        assert len(result) == 2
        assert result[0]["module_name"] == "sqli-scanner"
        assert result[1]["error_message"] == "Connection refused"

    def test_error_deduplication(self, db):
        session = ScanSession(name="errored-scan")
        session.start()
        errors = [
            {"module": "sqli-scanner", "target": "x.com", "stage": "scan", "error": "Timeout"},
        ]
        asyncio.run(db.save_scan(session, [], errors=errors))
        asyncio.run(db.save_scan(session, [], errors=errors))

        result = asyncio.run(db.get_scan_errors(session.id))
        assert len(result) == 1
