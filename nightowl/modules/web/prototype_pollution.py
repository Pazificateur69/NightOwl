"""Prototype pollution scanner for JavaScript applications."""

import logging
from urllib.parse import urlencode

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

PP_PAYLOADS = [
    {"__proto__[nightowl]": "polluted"},
    {"__proto__.nightowl": "polluted"},
    {"constructor[prototype][nightowl]": "polluted"},
    {"constructor.prototype.nightowl": "polluted"},
    {"__proto__[status]": "polluted"},
    {"__proto__[constructor]": "polluted"},
]

PP_JSON_PAYLOADS = [
    '{"__proto__":{"nightowl":"polluted"}}',
    '{"constructor":{"prototype":{"nightowl":"polluted"}}}',
]


class PrototypePollutionPlugin(ScannerPlugin):
    name = "prototype-pollution"
    description = "Detect client-side and server-side JavaScript prototype pollution"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                baseline = await client.get(url)

                # Test via query parameters
                for payload in PP_PAYLOADS:
                    test_url = f"{url}{'&' if '?' in url else '?'}{urlencode(payload)}"
                    try:
                        resp = await client.get(test_url)
                        if "polluted" in resp.text and "polluted" not in baseline.text:
                            findings.append(Finding(
                                title="Server-side Prototype Pollution (query params)",
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                description="Prototype pollution via query parameters leads to property injection",
                                evidence=f"URL: {test_url}\nPayload: {payload}\n'polluted' reflected in response",
                                remediation="Sanitize user input. Use Object.create(null). Freeze prototypes. Validate object keys.",
                                category="prototype-pollution",
                                references=["https://portswigger.net/research/server-side-prototype-pollution"],
                            ))
                            break
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        continue

                # Test via JSON body
                for payload in PP_JSON_PAYLOADS:
                    try:
                        resp = await client.post(url, content=payload, headers={"Content-Type": "application/json"})
                        if resp.status_code == 500:
                            findings.append(Finding(
                                title="Potential Prototype Pollution (JSON body crash)",
                                severity=Severity.HIGH,
                                cvss_score=7.5,
                                description="Server crashes with prototype pollution JSON payload",
                                evidence=f"URL: {url}\nPayload: {payload}\nResponse: {resp.status_code}",
                                remediation="Validate JSON input. Block __proto__ and constructor keys.",
                                category="prototype-pollution",
                            ))
                            break
                        if "polluted" in resp.text:
                            findings.append(Finding(
                                title="Server-side Prototype Pollution (JSON body)",
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                evidence=f"URL: {url}\nPayload: {payload}",
                                remediation="Block __proto__ and constructor.prototype in JSON parsing.",
                                category="prototype-pollution",
                            ))
                            break
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        continue

        except Exception as e:
            logger.warning(f"Prototype pollution scan failed: {e}")

        return findings
