"""CORS misconfiguration checker plugin."""

import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, FindingState, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.example.com",
    "https://subdomain.evil.com",
    "https://evil-mirror.com",
]


class CORSCheckerPlugin(ScannerPlugin):
    name = "cors-checker"
    description = "Detect CORS misconfigurations"
    version = "1.1.0"
    stage = "scan"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.test_origins: list[str] = self.config.get("test_origins", TEST_ORIGINS)

    async def _check_preflight(
        self, client: httpx.AsyncClient, url: str, origin: str
    ) -> dict | None:
        """Send an OPTIONS preflight request and return CORS headers."""
        try:
            resp = await client.options(
                url,
                headers=self.get_request_headers({
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                }),
            )
            return {
                "acao": resp.headers.get("access-control-allow-origin", ""),
                "acac": resp.headers.get("access-control-allow-credentials", ""),
                "acam": resp.headers.get("access-control-allow-methods", ""),
                "acah": resp.headers.get("access-control-allow-headers", ""),
                "acma": resp.headers.get("access-control-max-age", ""),
                "status": resp.status_code,
            }
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            return None

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"
        reflected_origins: list[tuple[str, str]] = []
        allow_credentials = False
        saw_null_origin = False
        wildcard_with_credentials = False
        dangerous_methods: set[str] = set()
        dangerous_methods_exposed = False
        preflight_issues: list[str] = []

        try:
            async with self.create_http_client() as client:
                for origin in self.test_origins:
                    # Test GET request
                    try:
                        resp = await client.get(url, headers=self.get_request_headers({"Origin": origin}))
                        acao = resp.headers.get("access-control-allow-origin", "")
                        acac = resp.headers.get("access-control-allow-credentials", "")

                        if acao == "*" and acac.lower() == "true":
                            wildcard_with_credentials = True
                        elif acao == origin and origin != "null":
                            reflected_origins.append((origin, acao))
                            allow_credentials = allow_credentials or acac.lower() == "true"
                        elif acao == "null":
                            saw_null_origin = True
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        continue
                    await self.wait_request_delay()

                    # Test OPTIONS preflight
                    preflight = await self._check_preflight(client, url, origin)
                    if preflight:
                        pf_acao = preflight["acao"]
                        if pf_acao == origin or (
                            pf_acao == "*" and preflight["acac"].lower() == "true"
                        ):
                            dangerous_methods_exposed = True
                            methods = preflight["acam"].upper()
                            for m in ("PUT", "DELETE", "PATCH"):
                                if m in methods:
                                    dangerous_methods.add(m)

                        # Check for overly long max-age (cache poisoning risk)
                        if preflight["acma"]:
                            try:
                                max_age = int(preflight["acma"])
                                if max_age > 86400:
                                    preflight_issues.append(
                                        f"Excessive preflight cache max-age: {max_age}s "
                                        f"(>24h) for origin {origin}"
                                    )
                            except ValueError:
                                pass
                    await self.wait_request_delay()

                # Test POST request with a reflected origin
                if reflected_origins:
                    test_origin = reflected_origins[0][0]
                    try:
                        resp = await client.post(
                            url,
                            headers=self.get_request_headers({"Origin": test_origin}),
                            content="",
                        )
                        post_acao = resp.headers.get("access-control-allow-origin", "")
                        post_acac = resp.headers.get("access-control-allow-credentials", "")
                        if post_acao == test_origin and post_acac.lower() == "true":
                            allow_credentials = True
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")

        except Exception as e:
            logger.warning(f"CORS check failed: {e}")

        if wildcard_with_credentials:
            findings.append(Finding(
                title="CORS: Wildcard with credentials",
                severity=Severity.HIGH, cvss_score=7.5,
                finding_state=FindingState.CONFIRMED,
                confidence_score=0.98,
                description="CORS allows any origin with credentials, enabling data theft",
                evidence="Server returned Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
                remediation="Never combine wildcard origins with allow-credentials. Whitelist specific trusted origins.",
                category="cors",
            ))

        if len(reflected_origins) >= 2:
            sev = Severity.HIGH if allow_credentials else Severity.MEDIUM
            findings.append(Finding(
                title="CORS reflects arbitrary origins",
                severity=sev,
                finding_state=FindingState.CONFIRMED if allow_credentials else FindingState.SUSPECTED,
                confidence_score=0.95 if allow_credentials else 0.8,
                cvss_score=6.5 if sev == Severity.HIGH else 4.3,
                description="Server reflects multiple attacker-controlled Origin values in CORS responses.",
                evidence=(
                    "Reflected origins:\n" +
                    "\n".join(
                        f"Origin: {origin}\nReturned ACAO: {acao}"
                        for origin, acao in reflected_origins
                    ) +
                    f"\nCredentials allowed: {allow_credentials}"
                ),
                remediation="Validate the Origin header against a strict allowlist of trusted domains.",
                category="cors",
            ))

        if saw_null_origin:
            findings.append(Finding(
                title="CORS allows null origin",
                severity=Severity.MEDIUM, cvss_score=4.3,
                finding_state=FindingState.SUSPECTED,
                confidence_score=0.8,
                description="Server allows null origin which can be exploited via sandboxed iframes",
                evidence="Access-Control-Allow-Origin: null",
                remediation="Do not allow null as a valid origin.",
                category="cors",
            ))

        if dangerous_methods and dangerous_methods_exposed:
            findings.append(Finding(
                title=f"CORS allows dangerous methods: {', '.join(sorted(dangerous_methods))}",
                severity=Severity.MEDIUM, cvss_score=4.3,
                finding_state=FindingState.SUSPECTED,
                confidence_score=0.85,
                description=(
                    f"Preflight responses allow state-changing HTTP methods "
                    f"({', '.join(sorted(dangerous_methods))}) from arbitrary origins."
                ),
                evidence=f"Allowed methods: {', '.join(sorted(dangerous_methods))}",
                remediation="Restrict Access-Control-Allow-Methods to only the methods required by legitimate origins.",
                category="cors",
            ))

        if preflight_issues:
            findings.append(Finding(
                title="CORS preflight configuration issues",
                severity=Severity.LOW, cvss_score=2.6,
                finding_state=FindingState.INFO,
                confidence_score=0.75,
                description="Preflight response configuration may increase attack surface.",
                evidence="\n".join(preflight_issues),
                remediation="Set Access-Control-Max-Age to a reasonable value (e.g., 3600) and review preflight responses.",
                category="cors",
            ))

        return findings
