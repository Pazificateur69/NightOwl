"""WebSocket security testing and fuzzing plugin.

Discovers WebSocket endpoints, tests for authentication bypass,
and fuzzes with various payloads to detect injection vulnerabilities.
"""

import asyncio
import json
import logging
from urllib.parse import urlparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

try:
    import websockets
    import websockets.client

    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    logger.debug("websockets library not installed; WebSocket fuzzer will use fallback detection")

# Common WebSocket endpoint paths
WS_PATHS = [
    "/ws",
    "/websocket",
    "/socket",
    "/ws/",
    "/wss",
    "/socket.io/",
    "/sockjs/",
    "/realtime",
    "/live",
    "/stream",
    "/api/ws",
    "/api/websocket",
    "/graphql",
    "/subscriptions",
    "/cable",
    "/hub",
    "/signalr",
    "/echo",
    "/chat",
]

# Fuzzing payloads organized by attack type
FUZZ_PAYLOADS: dict[str, list[str]] = {
    "xss": [
        '<script>alert("NightOwl")</script>',
        '<img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        "javascript:alert(document.cookie)",
    ],
    "sqli": [
        "' OR '1'='1' --",
        "1; DROP TABLE users --",
        "' UNION SELECT NULL,NULL,NULL--",
        "admin'--",
    ],
    "command_injection": [
        "; ls -la /",
        "| cat /etc/passwd",
        "`id`",
        "$(whoami)",
        "& ping -c 1 127.0.0.1",
    ],
    "path_traversal": [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "format_string": [
        "%s%s%s%s%s%s%s",
        "%x%x%x%x%x",
        "{0.__class__.__mro__}",
    ],
    "overflow": [
        "A" * 10000,
        "A" * 65536,
    ],
}

# Indicators of successful injection in responses
INJECTION_INDICATORS: dict[str, list[str]] = {
    "xss": ["<script>", "onerror=", "alert("],
    "sqli": ["sql", "syntax error", "unclosed quotation", "mysql", "postgresql", "sqlite", "ORA-"],
    "command_injection": ["root:", "uid=", "/bin/", "total ", "drwx"],
    "path_traversal": ["root:x:0:0", "[boot loader]", "daemon:"],
    "format_string": ["0x", "(nil)", "class"],
}


class WebSocketFuzzerPlugin(ScannerPlugin):
    name = "websocket-fuzzer"
    description = "Discover and fuzz WebSocket endpoints for security vulnerabilities"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=10
            ) as client:
                # ── Phase 1: Discover WebSocket endpoints ──
                ws_endpoints = await self._discover_ws_endpoints(
                    client, parsed, url
                )

                if not ws_endpoints:
                    logger.info(f"No WebSocket endpoints found on {target.host}")
                    return findings

                for ws_url in ws_endpoints:
                    findings.append(
                        Finding(
                            title=f"WebSocket Endpoint Discovered: {ws_url}",
                            severity=Severity.INFO,
                            cvss_score=0.0,
                            description=f"Active WebSocket endpoint found at {ws_url}",
                            evidence=f"Endpoint: {ws_url}",
                            category="websocket",
                        )
                    )

                if not HAS_WEBSOCKETS:
                    findings.append(
                        Finding(
                            title="WebSocket Fuzzing Skipped: Library Not Installed",
                            severity=Severity.INFO,
                            cvss_score=0.0,
                            description=(
                                "The 'websockets' library is not installed. "
                                "Install it with 'pip install websockets' for full WebSocket fuzzing."
                            ),
                            evidence=f"Endpoints found but not fuzzed: {', '.join(ws_endpoints)}",
                            category="websocket",
                        )
                    )
                    return findings

                # ── Phase 2: Test each endpoint ──
                for ws_url in ws_endpoints:
                    # Test unauthenticated connection
                    auth_finding = await self._test_auth_bypass(ws_url)
                    if auth_finding:
                        findings.append(auth_finding)

                    # Fuzz with payloads
                    fuzz_findings = await self._fuzz_endpoint(ws_url)
                    findings.extend(fuzz_findings)

        except Exception as e:
            logger.warning(f"WebSocket fuzzer failed: {e}")

        return findings

    async def _discover_ws_endpoints(
        self,
        client: httpx.AsyncClient,
        parsed: urlparse,
        url: str,
    ) -> list[str]:
        """Discover WebSocket endpoints via HTTP upgrade probes."""
        found: list[str] = []
        base = f"{parsed.scheme}://{parsed.netloc}"
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"

        for path in WS_PATHS:
            probe_url = f"{base}{path}"
            try:
                resp = await client.get(
                    probe_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    },
                )
                # 101 Switching Protocols or 426 Upgrade Required both indicate WS support
                if resp.status_code == 101:
                    found.append(f"{ws_scheme}://{parsed.netloc}{path}")
                elif resp.status_code == 426:
                    found.append(f"{ws_scheme}://{parsed.netloc}{path}")
                elif resp.status_code == 400:
                    # Some servers return 400 for invalid WS handshake but reveal support
                    upgrade_header = resp.headers.get("upgrade", "").lower()
                    if "websocket" in upgrade_header:
                        found.append(f"{ws_scheme}://{parsed.netloc}{path}")

            except Exception:
                continue

        # Also check if the main page references WebSocket URLs
        try:
            resp = await client.get(url)
            body = resp.text
            # Look for ws:// or wss:// URLs in page source
            import re

            ws_pattern = re.compile(r"wss?://[^\s\"'<>]+")
            for match in ws_pattern.finditer(body):
                ws_url = match.group(0).rstrip("\"';),")
                if ws_url not in found:
                    found.append(ws_url)
        except Exception:
            pass

        return list(dict.fromkeys(found))  # dedupe, preserve order

    async def _test_auth_bypass(self, ws_url: str) -> Finding | None:
        """Test if WebSocket connects without credentials."""
        if not HAS_WEBSOCKETS:
            return None

        try:
            async with asyncio.timeout(5):
                async with websockets.client.connect(
                    ws_url,
                    additional_headers={},
                    open_timeout=5,
                    close_timeout=2,
                ) as ws:
                    # Connection succeeded without any auth
                    # Try sending a message to confirm it's functional
                    try:
                        await ws.send('{"type":"ping"}')
                        response = await asyncio.wait_for(ws.recv(), timeout=3)
                        return Finding(
                            title=f"WebSocket Authentication Bypass: {ws_url}",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=(
                                "WebSocket endpoint accepts connections without authentication. "
                                "An attacker can connect and interact with the WebSocket service."
                            ),
                            evidence=(
                                f"Endpoint: {ws_url}\n"
                                f"Sent: {{\"type\":\"ping\"}}\n"
                                f"Received: {str(response)[:200]}"
                            ),
                            remediation=(
                                "Implement authentication for WebSocket connections. "
                                "Validate tokens/cookies during the handshake. "
                                "Use Origin header validation."
                            ),
                            category="websocket",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets",
                            ],
                        )
                    except Exception:
                        # Connected but no response -- still an auth issue
                        return Finding(
                            title=f"WebSocket Unauthenticated Connection: {ws_url}",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            description="WebSocket endpoint accepts unauthenticated connections.",
                            evidence=f"Endpoint: {ws_url}\nConnection established without credentials.",
                            remediation="Require authentication during WebSocket handshake.",
                            category="websocket",
                        )
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"WS auth test for {ws_url}: {e}")

        return None

    async def _fuzz_endpoint(self, ws_url: str) -> list[Finding]:
        """Send fuzzing payloads through WebSocket and analyze responses."""
        findings: list[Finding] = []
        if not HAS_WEBSOCKETS:
            return findings

        for attack_type, payloads in FUZZ_PAYLOADS.items():
            for payload in payloads:
                try:
                    async with asyncio.timeout(8):
                        async with websockets.client.connect(
                            ws_url, open_timeout=5, close_timeout=2
                        ) as ws:
                            # Send payload both raw and in JSON wrapper
                            for msg in [payload, json.dumps({"message": payload})]:
                                try:
                                    await ws.send(msg)
                                    response = await asyncio.wait_for(
                                        ws.recv(), timeout=3
                                    )
                                    resp_lower = response.lower() if isinstance(response, str) else ""

                                    # Check for injection indicators
                                    indicators = INJECTION_INDICATORS.get(attack_type, [])
                                    for indicator in indicators:
                                        if indicator.lower() in resp_lower:
                                            severity = (
                                                Severity.CRITICAL
                                                if attack_type in ("command_injection", "sqli")
                                                else Severity.HIGH
                                            )
                                            cvss = 9.0 if severity == Severity.CRITICAL else 7.5
                                            findings.append(
                                                Finding(
                                                    title=f"WebSocket {attack_type.replace('_', ' ').title()} Detected",
                                                    severity=severity,
                                                    cvss_score=cvss,
                                                    description=(
                                                        f"WebSocket endpoint is vulnerable to {attack_type} injection. "
                                                        f"Indicator '{indicator}' found in response."
                                                    ),
                                                    evidence=(
                                                        f"Endpoint: {ws_url}\n"
                                                        f"Payload: {payload[:100]}\n"
                                                        f"Indicator: {indicator}\n"
                                                        f"Response: {str(response)[:200]}"
                                                    ),
                                                    remediation=(
                                                        "Validate and sanitize all WebSocket input. "
                                                        "Apply the same security controls as HTTP endpoints."
                                                    ),
                                                    category="websocket",
                                                )
                                            )
                                            break
                                except asyncio.TimeoutError:
                                    continue
                                except Exception:
                                    continue

                            # Check for oversized message handling
                            if attack_type == "overflow":
                                try:
                                    await ws.send(payload)
                                except Exception as e:
                                    if "too large" not in str(e).lower():
                                        # Server didn't properly reject oversized message
                                        pass

                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue

        return findings
