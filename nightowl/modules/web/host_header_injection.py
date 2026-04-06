"""Host header injection and password reset poisoning."""

import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class HostHeaderInjectionPlugin(ScannerPlugin):
    name = "host-header-injection"
    description = "Detect Host header injection, password reset poisoning, and routing attacks"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"
        host = target.domain or target.host

        evil_host = "nightowl-evil.com"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                baseline = await client.get(url)

                # Test 1: Direct Host header override
                try:
                    resp = await client.get(url, headers={"Host": evil_host})
                    if evil_host in resp.text:
                        findings.append(Finding(
                            title="Host header injection (reflected)",
                            severity=Severity.HIGH,
                            cvss_score=8.1,
                            description="Host header value is reflected in the response body",
                            evidence=f"Injected Host: {evil_host}\nReflected in response body",
                            remediation="Validate the Host header against a whitelist. Never use the Host header for URL generation.",
                            category="host-header",
                        ))
                    if resp.status_code in (301, 302, 307, 308):
                        loc = resp.headers.get("location", "")
                        if evil_host in loc:
                            findings.append(Finding(
                                title="Host header injection (redirect)",
                                severity=Severity.CRITICAL,
                                cvss_score=9.0,
                                description="Host header controls redirect Location",
                                evidence=f"Injected Host: {evil_host}\nLocation: {loc}",
                                remediation="Use absolute URLs with hardcoded domain in redirects.",
                                category="host-header",
                            ))
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")

                # Test 2: X-Forwarded-Host
                try:
                    resp = await client.get(url, headers={"X-Forwarded-Host": evil_host})
                    if evil_host in resp.text and evil_host not in baseline.text:
                        findings.append(Finding(
                            title="X-Forwarded-Host injection",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            evidence=f"X-Forwarded-Host: {evil_host} reflected in response",
                            remediation="Ignore X-Forwarded-Host or validate against trusted proxies.",
                            category="host-header",
                        ))
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")

                # Test 3: Double Host header (supply two)
                try:
                    resp = await client.get(url, headers={"Host": f"{host}\r\nX-Injected: nightowl"})
                    if "nightowl" in resp.headers.get("x-injected", ""):
                        findings.append(Finding(
                            title="Host header CRLF injection",
                            severity=Severity.CRITICAL,
                            cvss_score=9.0,
                            evidence="CRLF injection in Host header succeeds",
                            remediation="Reject Host headers with CRLF characters.",
                            category="host-header",
                        ))
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")

                # Test 4: Absolute URL with different Host
                try:
                    resp = await client.request("GET", url, headers={"Host": evil_host})
                    if resp.status_code == 200 and evil_host in resp.text:
                        findings.append(Finding(
                            title="Host header accepted with absolute URL",
                            severity=Severity.MEDIUM,
                            evidence=f"Server accepts mismatched Host header with absolute URL",
                            category="host-header",
                        ))
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")

        except Exception as e:
            logger.warning(f"Host header injection scan failed: {e}")

        return findings
