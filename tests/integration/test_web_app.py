"""Integration tests for the FastAPI dashboard and API."""

import asyncio

from fastapi.testclient import TestClient

from nightowl.db.database import Database
from nightowl.models.config import NightOwlConfig, ScopeConfig
from nightowl.models.finding import Finding, FindingState, Severity
from nightowl.models.scan import ScanMode, ScanSession
from nightowl.models.target import Target
from nightowl.web.app import create_app
from nightowl.web.routers import api as api_router


def _create_config(tmp_path):
    return NightOwlConfig(
        mode="auto",
        db_path=str(tmp_path / "nightowl-test.db"),
        output_dir=str(tmp_path / "reports"),
        scope=ScopeConfig(allowed_hosts=["127.0.0.1", "example.com"]),
    )


def _save_scan_with_data(config, *, scan_id="scan-1", findings=None, errors=None):
    async def _save():
        db = Database(config.db_path)
        await db.init()
        session = ScanSession(
            id=scan_id,
            name="integration-scan",
            targets=[Target(host="example.com")],
            mode=ScanMode.AUTO,
            modules_enabled=["xss-scanner"],
        )
        session.start()
        session.complete(findings_count=len(findings or []))
        await db.save_scan(session, findings or [], errors=errors or [])
        return session

    return asyncio.run(_save())


def test_dashboard_renders_core_modules_and_recent_scans(tmp_path):
    config = _create_config(tmp_path)
    finding = Finding(
        title="Reflected XSS",
        severity=Severity.HIGH,
        finding_state=FindingState.SUSPECTED,
        confidence_score=0.83,
        target="example.com",
        module_name="xss-scanner",
        metadata={"module_maturity": "recommended"},
    )
    _save_scan_with_data(config, findings=[finding])

    client = TestClient(create_app(config))
    response = client.get("/")

    assert response.status_code == 200
    assert "Core Modules" in response.text
    assert "Module Maturity" in response.text
    assert "Benchmark Evidence" in response.text
    assert "Delta From Previous Run" in response.text
    assert "quiet_expected" in response.text
    assert "focus artifact:" in response.text
    assert "integration-scan" in response.text
    assert "xss-scanner" in response.text
    assert "confirmed_hit" in response.text


def test_scan_detail_renders_state_confidence_and_maturity(tmp_path):
    config = _create_config(tmp_path)
    finding = Finding(
        title="Reflected XSS",
        severity=Severity.HIGH,
        finding_state=FindingState.SUSPECTED,
        confidence_score=0.83,
        target="example.com",
        module_name="xss-scanner",
        metadata={"module_maturity": "recommended"},
    )
    session = _save_scan_with_data(config, findings=[finding], scan_id="scan-detail")

    client = TestClient(create_app(config))
    response = client.get(f"/scans/{session.id}")

    assert response.status_code == 200
    assert "Reflected XSS" in response.text
    assert "SUSPECTED" in response.text
    assert "0.83" in response.text
    assert "recommended" in response.text


def test_api_returns_findings_stats_and_errors(tmp_path):
    config = _create_config(tmp_path)
    finding = Finding(
        title="Open Port 22",
        severity=Severity.INFO,
        finding_state=FindingState.INFO,
        confidence_score=0.99,
        target="example.com",
        module_name="port-scanner",
        metadata={"module_maturity": "recommended"},
    )
    session = _save_scan_with_data(
        config,
        findings=[finding],
        errors=[{"module": "ssl-analyzer", "target": "example.com", "stage": "scan", "error": "timeout"}],
        scan_id="scan-api",
    )

    client = TestClient(create_app(config))

    findings_response = client.get(f"/api/scans/{session.id}/findings")
    stats_response = client.get(f"/api/scans/{session.id}/stats")
    errors_response = client.get(f"/api/scans/{session.id}/errors")

    assert findings_response.status_code == 200
    assert findings_response.json()[0]["title"] == "Open Port 22"
    assert findings_response.json()[0]["confidence_score"] == 0.99

    assert stats_response.status_code == 200
    assert stats_response.json()["info"] == 1

    assert errors_response.status_code == 200
    assert errors_response.json()[0]["module_name"] == "ssl-analyzer"
    assert errors_response.json()[0]["error_message"] == "timeout"


def test_api_create_scan_returns_placeholder_session(tmp_path, monkeypatch):
    config = _create_config(tmp_path)

    async def _fake_run_scan_background(config, session_id, targets, mode, modules):
        return None

    monkeypatch.setattr(api_router, "_run_scan_background", _fake_run_scan_background)

    client = TestClient(create_app(config))
    response = client.post(
        "/api/scans",
        json={"targets": ["127.0.0.1"], "mode": "auto", "modules": []},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "running"
    assert "id" in payload

    scan_response = client.get(f"/api/scans/{payload['id']}")
    assert scan_response.status_code == 200
    assert scan_response.json()["status"] == "running"


def test_api_generate_html_report_returns_output_path(tmp_path):
    config = _create_config(tmp_path)
    finding = Finding(
        title="Missing HSTS",
        severity=Severity.MEDIUM,
        finding_state=FindingState.SUSPECTED,
        confidence_score=0.9,
        target="example.com",
        module_name="header-analyzer",
        metadata={"module_maturity": "recommended"},
    )
    session = _save_scan_with_data(config, findings=[finding], scan_id="scan-report")

    client = TestClient(create_app(config))
    response = client.get(f"/api/reports/{session.id}?fmt=html")

    assert response.status_code == 200
    path = response.json()["path"]
    assert path.endswith(".html")
