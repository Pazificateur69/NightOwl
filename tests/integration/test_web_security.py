"""Tests for web app security: headers, CORS, auth, input validation."""

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from nightowl.models.config import NightOwlConfig, ScopeConfig
from nightowl.web.app import create_app
from nightowl.web.routers import api as api_router


@pytest.fixture
def config(tmp_path):
    return NightOwlConfig(
        mode="auto",
        db_path=str(tmp_path / "test.db"),
        output_dir=str(tmp_path / "reports"),
        scope=ScopeConfig(
            allowed_hosts=["127.0.0.1", "example.com"],
            allowed_ips=["192.168.1.1"],
            allowed_networks=["192.168.1.0/24"],
        ),
    )


@pytest.fixture
def client(config):
    return TestClient(create_app(config))


# ---------- Security Headers ----------

class TestSecurityHeaders:
    def test_x_frame_options_set(self, client):
        resp = client.get("/")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_x_content_type_options_set(self, client):
        resp = client.get("/")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_referrer_policy_set(self, client):
        resp = client.get("/")
        assert "strict-origin" in resp.headers.get("referrer-policy", "")

    def test_permissions_policy_set(self, client):
        resp = client.get("/")
        assert "camera=()" in resp.headers.get("permissions-policy", "")

    def test_csp_set(self, client):
        resp = client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp

    def test_api_also_has_security_headers(self, client):
        resp = client.get("/api/scans")
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("x-content-type-options") == "nosniff"


# ---------- API Key Authentication ----------

class TestAPIKeyAuth:
    def test_no_auth_when_env_not_set(self, config):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NIGHTOWL_API_KEY", None)
            client = TestClient(create_app(config))
            resp = client.get("/api/scans")
            assert resp.status_code == 200

    def test_401_when_key_required_but_missing(self, config):
        with patch.dict(os.environ, {"NIGHTOWL_API_KEY": "secret-test-key"}):
            client = TestClient(create_app(config))
            resp = client.get("/api/scans")
            assert resp.status_code == 401

    def test_401_when_key_wrong(self, config):
        with patch.dict(os.environ, {"NIGHTOWL_API_KEY": "secret-test-key"}):
            client = TestClient(create_app(config))
            resp = client.get("/api/scans", headers={"X-API-Key": "wrong-key"})
            assert resp.status_code == 401

    def test_200_when_key_correct_in_header(self, config):
        with patch.dict(os.environ, {"NIGHTOWL_API_KEY": "secret-test-key"}):
            client = TestClient(create_app(config))
            resp = client.get("/api/scans", headers={"X-API-Key": "secret-test-key"})
            assert resp.status_code == 200

    def test_200_when_key_correct_in_query(self, config):
        with patch.dict(os.environ, {"NIGHTOWL_API_KEY": "secret-test-key"}):
            client = TestClient(create_app(config))
            resp = client.get("/api/scans?api_key=secret-test-key")
            assert resp.status_code == 200


# ---------- Input Validation ----------

class TestScanInputValidation:
    @pytest.fixture(autouse=True)
    def _mock_scan(self, monkeypatch):
        async def _fake(*args, **kwargs):
            return None
        monkeypatch.setattr(api_router, "_run_scan_background", _fake)

    def test_empty_targets_rejected(self, client):
        resp = client.post("/api/scans", json={"targets": []})
        assert resp.status_code == 422

    def test_invalid_target_format_rejected(self, client):
        resp = client.post("/api/scans", json={"targets": [";;;invalid;;;"]})
        assert resp.status_code == 422

    def test_too_many_targets_rejected(self, client):
        targets = [f"10.0.0.{i}" for i in range(101)]
        resp = client.post("/api/scans", json={"targets": targets})
        assert resp.status_code == 422

    def test_valid_ip_target_accepted(self, client):
        resp = client.post("/api/scans", json={"targets": ["192.168.1.1"]})
        assert resp.status_code == 200

    def test_valid_domain_target_accepted(self, client):
        resp = client.post("/api/scans", json={"targets": ["example.com"]})
        assert resp.status_code == 200

    def test_valid_url_target_accepted(self, client):
        resp = client.post("/api/scans", json={"targets": ["https://example.com/path"]})
        assert resp.status_code == 200

    def test_valid_cidr_target_accepted(self, client):
        resp = client.post("/api/scans", json={"targets": ["192.168.1.0/24"]})
        assert resp.status_code == 200

    def test_out_of_scope_target_rejected(self, client):
        resp = client.post("/api/scans", json={"targets": ["evil.example.org"]})
        assert resp.status_code == 403


# ---------- Scan ID Sanitization ----------

class TestScanIDSanitization:
    def test_valid_scan_id(self, client):
        resp = client.get("/api/scans/scan-abc-123")
        # 404 is fine — the ID format is valid, just doesn't exist
        assert resp.status_code == 404

    def test_special_chars_scan_id_rejected(self, client):
        # Encode special chars to avoid FastAPI path normalization
        resp = client.get("/api/scans/scan%27%3B%20DROP%20TABLE--")
        assert resp.status_code == 400

    def test_dots_in_scan_id_rejected(self, client):
        resp = client.get("/api/scans/scan..id")
        assert resp.status_code == 400

    def test_spaces_in_scan_id_rejected(self, client):
        resp = client.get("/api/scans/scan%20id%20here")
        assert resp.status_code == 400
