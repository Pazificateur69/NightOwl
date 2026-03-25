"""API endpoint discovery and scanner plugin."""

import asyncio
import logging

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql",
    "/swagger.json", "/swagger/", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc", "/api-docs",
    "/api/health", "/api/status", "/api/version",
    "/rest", "/v1", "/v2",
    "/.well-known/openid-configuration",
    "/actuator", "/actuator/health", "/actuator/env",
]


class APIScannerPlugin(ScannerPlugin):
    name = "api-scanner"
    description = "Discover and test API endpoints"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = (target.url or f"https://{target.host}").rstrip("/")

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as client:
                for path in API_PATHS:
                    url = f"{base_url}{path}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            content_type = resp.headers.get("content-type", "")
                            is_json = "json" in content_type or resp.text.strip().startswith(("{", "["))

                            sev = Severity.INFO
                            desc = f"API endpoint accessible at {path}"

                            # Sensitive endpoints
                            if "actuator/env" in path or "swagger" in path or "openapi" in path:
                                sev = Severity.MEDIUM
                                desc = f"Sensitive API documentation/config exposed at {path}"

                            if "graphiql" in path or "graphql" in path:
                                if "graphiql" in resp.text.lower() or "__schema" in resp.text:
                                    sev = Severity.MEDIUM
                                    desc = f"GraphQL introspection/playground accessible at {path}"

                            findings.append(Finding(
                                title=f"API endpoint: {path} ({resp.status_code})",
                                severity=sev,
                                description=desc,
                                evidence=f"URL: {url}\nStatus: {resp.status_code}\nContent-Type: {content_type}\nJSON: {is_json}\nBody preview: {resp.text[:200]}",
                                category="api",
                            ))

                        elif resp.status_code == 401 or resp.status_code == 403:
                            findings.append(Finding(
                                title=f"Protected API endpoint: {path} ({resp.status_code})",
                                severity=Severity.INFO,
                                description=f"API endpoint exists but requires authentication",
                                evidence=f"URL: {url}\nStatus: {resp.status_code}",
                                category="api",
                            ))

                    except Exception:
                        continue
                    await asyncio.sleep(0.1)

        except Exception as e:
            logger.warning(f"API scan failed: {e}")

        return findings
