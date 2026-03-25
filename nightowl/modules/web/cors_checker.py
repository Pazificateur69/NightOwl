"""CORS misconfiguration checker plugin."""

import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

TEST_ORIGINS = ["https://evil.com", "null", "https://attacker.example.com"]


class CORSCheckerPlugin(ScannerPlugin):
    name = "cors-checker"
    description = "Detect CORS misconfigurations"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                for origin in TEST_ORIGINS:
                    try:
                        resp = await client.get(url, headers={"Origin": origin})
                        acao = resp.headers.get("access-control-allow-origin", "")
                        acac = resp.headers.get("access-control-allow-credentials", "")

                        if acao == "*" and acac.lower() == "true":
                            findings.append(Finding(
                                title="CORS: Wildcard with credentials",
                                severity=Severity.HIGH, cvss_score=7.5,
                                description="CORS allows any origin with credentials, enabling data theft",
                                evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                                remediation="Never combine wildcard origins with allow-credentials. Whitelist specific trusted origins.",
                                category="cors",
                            ))
                        elif origin in acao and origin != "null":
                            sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                            findings.append(Finding(
                                title=f"CORS reflects arbitrary origin: {origin}",
                                severity=sev, cvss_score=6.5 if sev == Severity.HIGH else 4.3,
                                description="Server reflects the Origin header in CORS response",
                                evidence=f"Sent Origin: {origin}\nReturned ACAO: {acao}\nCredentials: {acac}",
                                remediation="Validate the Origin header against a whitelist of trusted domains.",
                                category="cors",
                            ))
                        elif acao == "null":
                            findings.append(Finding(
                                title="CORS allows null origin",
                                severity=Severity.MEDIUM, cvss_score=4.3,
                                description="Server allows null origin which can be exploited via sandboxed iframes",
                                evidence=f"Access-Control-Allow-Origin: null",
                                remediation="Do not allow null as a valid origin.",
                                category="cors",
                            ))
                    except Exception:
                        continue

        except Exception as e:
            logger.warning(f"CORS check failed: {e}")

        return findings
