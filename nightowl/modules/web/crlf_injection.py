"""CRLF injection scanner plugin.

Tests URL parameters and redirect endpoints for HTTP header injection
via carriage return / line feed character sequences.
"""

import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Unique marker to detect injection in response headers
INJECTED_HEADER = "NightOwl-CRLF-Test"
INJECTED_VALUE = "CRLFInjected"

# CRLF payload variants
CRLF_PAYLOADS: list[tuple[str, str]] = [
    # Standard CRLF header injection
    (
        f"%0d%0a{INJECTED_HEADER}:{INJECTED_VALUE}",
        "URL-encoded CRLF",
    ),
    (
        f"%0D%0A{INJECTED_HEADER}:{INJECTED_VALUE}",
        "URL-encoded CRLF (uppercase)",
    ),
    (
        f"%0d%0a%0d%0a<html><body>NightOwlCRLFBody</body></html>",
        "CRLF with body injection (HTTP response splitting)",
    ),
    # Double encoding
    (
        f"%250d%250a{INJECTED_HEADER}:{INJECTED_VALUE}",
        "Double URL-encoded CRLF",
    ),
    # Unicode variants
    (
        f"%E5%98%8D%E5%98%8A{INJECTED_HEADER}:{INJECTED_VALUE}",
        "Unicode CRLF variant (UTF-8)",
    ),
    # Null byte + CRLF
    (
        f"%00%0d%0a{INJECTED_HEADER}:{INJECTED_VALUE}",
        "Null byte + CRLF",
    ),
    # Line feed only (some servers accept just LF)
    (
        f"%0a{INJECTED_HEADER}:{INJECTED_VALUE}",
        "LF-only injection",
    ),
    # Carriage return only
    (
        f"%0d{INJECTED_HEADER}:{INJECTED_VALUE}",
        "CR-only injection",
    ),
    # Set-Cookie injection for session fixation
    (
        "%0d%0aSet-Cookie:nightowl_test=injected;",
        "Set-Cookie header injection",
    ),
    # XSS via CRLF (inject Content-Type to render HTML)
    (
        "%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert('NightOwl')</script>",
        "Content-Type injection for XSS",
    ),
]

# Common parameter names used in redirects
REDIRECT_PARAMS = [
    "redirect",
    "url",
    "next",
    "return",
    "returnTo",
    "return_to",
    "goto",
    "dest",
    "destination",
    "rurl",
    "target",
    "redir",
    "redirect_uri",
    "redirect_url",
    "callback",
    "path",
    "continue",
    "forward",
    "location",
]


class CRLFInjectionPlugin(ScannerPlugin):
    name = "crlf-injection"
    description = "Test for HTTP header injection via CRLF sequences"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no params present, test common redirect parameters
        if not params:
            params = {p: ["test"] for p in REDIRECT_PARAMS[:8]}

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=False, timeout=10
            ) as client:
                confirmed_params: set[str] = set()

                for param_name in params:
                    if param_name in confirmed_params:
                        continue

                    for payload, payload_desc in CRLF_PAYLOADS:
                        if param_name in confirmed_params:
                            break

                        test_params = {
                            k: v[0] if isinstance(v, list) else v
                            for k, v in params.items()
                        }
                        test_params[param_name] = f"https://example.com{payload}"
                        # Manually build query to preserve CRLF encoding
                        query_parts = []
                        for k, v in test_params.items():
                            query_parts.append(f"{k}={v}")
                        test_url = urlunparse(
                            parsed._replace(query="&".join(query_parts))
                        )

                        try:
                            resp = await client.get(test_url)
                            finding = self._analyze_response(
                                resp, param_name, payload, payload_desc, test_url
                            )
                            if finding:
                                findings.append(finding)
                                confirmed_params.add(param_name)
                                break
                        except Exception:
                            continue

                    # Also test via POST body
                    if param_name in confirmed_params:
                        continue

                    for payload, payload_desc in CRLF_PAYLOADS[:4]:
                        try:
                            post_data = {param_name: f"https://example.com{payload}"}
                            resp = await client.post(url, data=post_data)
                            finding = self._analyze_response(
                                resp, param_name, payload, payload_desc, url
                            )
                            if finding:
                                finding.evidence += "\nMethod: POST"
                                findings.append(finding)
                                confirmed_params.add(param_name)
                                break
                        except Exception:
                            continue

                # ── Test path-based CRLF injection ──
                path_findings = await self._test_path_injection(client, parsed)
                findings.extend(path_findings)

        except Exception as e:
            logger.warning(f"CRLF injection scan failed: {e}")

        return findings

    def _analyze_response(
        self,
        resp: httpx.Response,
        param_name: str,
        payload: str,
        payload_desc: str,
        url: str,
    ) -> Finding | None:
        """Analyze response for evidence of CRLF injection."""

        # Check if our injected header appears in response headers
        injected_header_val = resp.headers.get(INJECTED_HEADER.lower(), "")
        if INJECTED_VALUE in injected_header_val:
            return Finding(
                title=f"CRLF Header Injection in '{param_name}'",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description=(
                    f"CRLF injection allows arbitrary HTTP header injection via parameter '{param_name}'. "
                    "An attacker can inject headers for session fixation (Set-Cookie), "
                    "cache poisoning, or HTTP response splitting (XSS)."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Parameter: {param_name}\n"
                    f"Payload type: {payload_desc}\n"
                    f"Injected header found: {INJECTED_HEADER}: {injected_header_val}"
                ),
                remediation=(
                    "Strip or encode CR (\\r, %0d) and LF (\\n, %0a) characters from all user input "
                    "before including it in HTTP headers. Use framework-provided header-setting methods "
                    "that handle encoding automatically."
                ),
                category="crlf-injection",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                    "https://cwe.mitre.org/data/definitions/113.html",
                ],
            )

        # Check for Set-Cookie injection
        set_cookie = resp.headers.get("set-cookie", "")
        if "nightowl_test=injected" in set_cookie:
            return Finding(
                title=f"CRLF Set-Cookie Injection in '{param_name}'",
                severity=Severity.HIGH,
                cvss_score=8.1,
                description=(
                    f"CRLF injection in parameter '{param_name}' allows Set-Cookie header injection. "
                    "An attacker can perform session fixation attacks."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Parameter: {param_name}\n"
                    f"Injected Set-Cookie: {set_cookie}"
                ),
                remediation="Sanitize CRLF characters from user input used in HTTP headers.",
                category="crlf-injection",
            )

        # Check for body injection (HTTP response splitting)
        if "NightOwlCRLFBody" in resp.text:
            return Finding(
                title=f"HTTP Response Splitting via '{param_name}'",
                severity=Severity.HIGH,
                cvss_score=8.1,
                description=(
                    f"CRLF injection in parameter '{param_name}' enables HTTP response splitting. "
                    "An attacker can inject a complete HTTP response body, enabling XSS and cache poisoning."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Parameter: {param_name}\n"
                    f"Payload type: {payload_desc}\n"
                    f"Injected body content found in response"
                ),
                remediation=(
                    "Strip CRLF sequences from all user input. "
                    "Use HTTP/2 where response splitting is not possible."
                ),
                category="crlf-injection",
            )

        # Check Location header for injection evidence
        location = resp.headers.get("location", "")
        if INJECTED_HEADER in location or INJECTED_VALUE in location:
            return Finding(
                title=f"CRLF Injection Evidence in Redirect '{param_name}'",
                severity=Severity.MEDIUM,
                cvss_score=5.4,
                description=(
                    f"CRLF characters in parameter '{param_name}' are reflected in the Location header. "
                    "Depending on the server and proxy chain, this may enable header injection."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Parameter: {param_name}\n"
                    f"Location header: {location[:200]}"
                ),
                remediation="Sanitize CRLF characters from redirect targets.",
                category="crlf-injection",
            )

        return None

    async def _test_path_injection(
        self, client: httpx.AsyncClient, parsed: urlparse
    ) -> list[Finding]:
        """Test for CRLF injection in the URL path."""
        findings: list[Finding] = []
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Some servers reflect the path in headers (e.g., in Location for trailing slash)
        path_payloads = [
            f"/nightowl%0d%0a{INJECTED_HEADER}:{INJECTED_VALUE}",
            f"/nightowl%0a{INJECTED_HEADER}:{INJECTED_VALUE}",
        ]

        for path_payload in path_payloads:
            try:
                test_url = f"{base}{path_payload}"
                resp = await client.get(test_url)

                injected_val = resp.headers.get(INJECTED_HEADER.lower(), "")
                if INJECTED_VALUE in injected_val:
                    findings.append(
                        Finding(
                            title="CRLF Injection in URL Path",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=(
                                "CRLF characters in the URL path are processed by the server, "
                                "allowing HTTP header injection."
                            ),
                            evidence=(
                                f"URL: {test_url}\n"
                                f"Injected header: {INJECTED_HEADER}: {injected_val}"
                            ),
                            remediation="URL-decode and sanitize path components. Reject paths with CRLF.",
                            category="crlf-injection",
                        )
                    )
                    break
            except Exception:
                continue

        return findings
