"""Comprehensive tests for SSLAnalyzerPlugin."""

import asyncio
import socket
import ssl
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from nightowl.models.target import Target
from nightowl.modules.web.ssl_analyzer import SSLAnalyzerPlugin


class TestWeakProtocolDetection:
    def test_tlsv1_0_is_weak(self):
        assert SSLAnalyzerPlugin._is_weak_protocol("TLSv1.0") is True

    def test_tlsv1_1_is_weak(self):
        assert SSLAnalyzerPlugin._is_weak_protocol("TLSv1.1") is True

    def test_sslv3_is_weak(self):
        assert SSLAnalyzerPlugin._is_weak_protocol("SSLv3") is True

    def test_tlsv1_2_is_not_weak(self):
        assert SSLAnalyzerPlugin._is_weak_protocol("TLSv1.2") is False

    def test_tlsv1_3_is_not_weak(self):
        assert SSLAnalyzerPlugin._is_weak_protocol("TLSv1.3") is False

    def test_none_is_not_weak(self):
        assert SSLAnalyzerPlugin._is_weak_protocol(None) is False


class TestCertDateParsing:
    def test_standard_format(self):
        dt = SSLAnalyzerPlugin._parse_cert_date("Jan 15 12:00:00 2025 GMT")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 1
        assert dt.day == 15

    def test_double_space_day(self):
        dt = SSLAnalyzerPlugin._parse_cert_date("Jan  5 12:00:00 2025 GMT")
        assert dt is not None
        assert dt.day == 5

    def test_invalid_string_returns_none(self):
        dt = SSLAnalyzerPlugin._parse_cert_date("not-a-date")
        assert dt is None

    def test_empty_string_returns_none(self):
        dt = SSLAnalyzerPlugin._parse_cert_date("")
        assert dt is None


class TestPortReachability:
    def test_unreachable_port_returns_false(self):
        # Port 1 is almost certainly not listening
        assert SSLAnalyzerPlugin._is_tls_port_open("127.0.0.1", 1, 0.5) is False


class TestRunHTTPTarget:
    def test_plain_http_target_returns_no_tls_finding(self):
        plugin = SSLAnalyzerPlugin()
        target = Target(host="http://example.com")
        findings = asyncio.run(plugin.run(target))
        assert len(findings) == 1
        assert "No TLS" in findings[0].title
        assert findings[0].severity.value == "medium"

    def test_plain_http_target_with_explicit_port_still_returns_no_tls_finding(self):
        plugin = SSLAnalyzerPlugin()
        target = Target(host="http://example.com:8080/app")
        findings = asyncio.run(plugin.run(target))
        assert len(findings) == 1
        assert findings[0].title == "No TLS — target uses plain HTTP"
        assert "8080" in findings[0].evidence

    def test_unreachable_port_returns_info_finding(self):
        plugin = SSLAnalyzerPlugin(config={"connect_timeout": 0.5})
        target = Target(host="192.0.2.1")  # RFC 5737 test address, unreachable
        target.port = 44399  # unlikely to be open
        with patch.object(SSLAnalyzerPlugin, "_is_tls_port_open", return_value=False):
            findings = asyncio.run(plugin.run(target))
        assert len(findings) == 1
        assert "not reachable" in findings[0].title

    def test_ssl_error_returns_handshake_failure(self):
        plugin = SSLAnalyzerPlugin(config={"connect_timeout": 1})
        target = Target(host="example.com")

        with patch.object(SSLAnalyzerPlugin, "_is_tls_port_open", return_value=True), \
             patch("socket.create_connection") as mock_conn:
            mock_conn.side_effect = ssl.SSLError(1, "[SSL] unknown")
            findings = asyncio.run(plugin.run(target))

        assert len(findings) == 1
        assert "handshake failed" in findings[0].title.lower()

    def test_weak_protocol_detected(self):
        plugin = SSLAnalyzerPlugin()
        target = Target(host="example.com")

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = None
        mock_ssock.cipher.return_value = ("AES256-GCM-SHA384", "TLSv1.0", 256)
        mock_ssock.version.return_value = "TLSv1.0"
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        with patch.object(SSLAnalyzerPlugin, "_is_tls_port_open", return_value=True), \
             patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            findings = asyncio.run(plugin.run(target))

        weak_findings = [f for f in findings if "Weak TLS" in f.title]
        assert len(weak_findings) == 1
        assert weak_findings[0].severity.value == "high"

    def test_expired_cert_detected(self):
        plugin = SSLAnalyzerPlugin()
        target = Target(host="example.com")

        yesterday = datetime.now() - timedelta(days=1)
        cert_date = yesterday.strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "notAfter": cert_date,
            "issuer": [[("commonName", "Test CA")]],
            "subject": [[("commonName", "example.com")]],
        }
        mock_ssock.cipher.return_value = ("AES256-GCM-SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        with patch.object(SSLAnalyzerPlugin, "_is_tls_port_open", return_value=True), \
             patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            findings = asyncio.run(plugin.run(target))

        expired = [f for f in findings if "expired" in f.title.lower()]
        assert len(expired) == 1

    def test_self_signed_cert_detected(self):
        plugin = SSLAnalyzerPlugin()
        target = Target(host="example.com")

        future = datetime.now() + timedelta(days=365)
        cert_date = future.strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "notAfter": cert_date,
            "issuer": [[("commonName", "self-signed")]],
            "subject": [[("commonName", "self-signed")]],
        }
        mock_ssock.cipher.return_value = ("AES256-GCM-SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        with patch.object(SSLAnalyzerPlugin, "_is_tls_port_open", return_value=True), \
             patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            findings = asyncio.run(plugin.run(target))

        self_signed = [f for f in findings if "Self-signed" in f.title]
        assert len(self_signed) == 1
