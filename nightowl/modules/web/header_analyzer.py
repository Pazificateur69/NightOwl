"""Security header analysis plugin.

Checks for missing security headers and information-leaking headers
in HTTP responses.
"""

import logging
from urllib.parse import urlparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, FindingState, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Security headers that should be present
SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "cvss": 6.1,
        "description": (
            "HTTP Strict Transport Security (HSTS) header is missing. "
            "This allows downgrade attacks and cookie hijacking via "
            "man-in-the-middle interception."
        ),
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload' to all HTTPS responses."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ],
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "cvss": 4.3,
        "description": (
            "X-Content-Type-Options header is missing. Browsers may "
            "MIME-sniff the response body, potentially executing "
            "untrusted content as an unexpected type."
        ),
        "remediation": "Add 'X-Content-Type-Options: nosniff' to all responses.",
        "references": [
            "https://owasp.org/www-project-secure-headers/#x-content-type-options",
        ],
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "cvss": 4.3,
        "description": (
            "X-Frame-Options header is missing. The page can be "
            "embedded in iframes, enabling clickjacking attacks."
        ),
        "remediation": (
            "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'. "
            "Consider also using CSP frame-ancestors directive."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "cvss": 5.4,
        "description": (
            "Content-Security-Policy header is missing. Without CSP, "
            "the application is more vulnerable to XSS and data injection "
            "attacks."
        ),
        "remediation": (
            "Implement a Content-Security-Policy header with restrictive "
            "directives. Start with 'Content-Security-Policy: default-src "
            "'self'' and refine as needed."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        ],
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "cvss": 3.1,
        "description": (
            "X-XSS-Protection header is missing. While modern browsers "
            "have deprecated this, it provides defense-in-depth for "
            "older browsers."
        ),
        "remediation": (
            "Add 'X-XSS-Protection: 0' if CSP is implemented, or "
            "'X-XSS-Protection: 1; mode=block' for legacy browser support."
        ),
        "references": [
            "https://owasp.org/www-project-secure-headers/#x-xss-protection",
        ],
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "cvss": 3.1,
        "description": (
            "Referrer-Policy header is missing. Sensitive information in "
            "URLs may leak via the Referer header to third-party sites."
        ),
        "remediation": (
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' or "
            "'Referrer-Policy: no-referrer' depending on requirements."
        ),
        "references": [
            "https://owasp.org/www-project-secure-headers/#referrer-policy",
        ],
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "cvss": 3.1,
        "description": (
            "Permissions-Policy header is missing. Browser features like "
            "camera, microphone, and geolocation are not explicitly restricted."
        ),
        "remediation": (
            "Add a Permissions-Policy header restricting unused browser "
            "features, e.g., 'Permissions-Policy: camera=(), microphone=(), "
            "geolocation=()'."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        ],
    },
}

# Headers that leak server information
INFO_LEAK_HEADERS: dict[str, dict] = {
    "Server": {
        "severity": Severity.INFO,
        "cvss": 0.0,
        "description": (
            "The Server header reveals web server software and potentially "
            "its version. This aids attackers in fingerprinting the target."
        ),
        "remediation": "Remove or genericize the Server header in your web server configuration.",
    },
    "X-Powered-By": {
        "severity": Severity.LOW,
        "cvss": 2.6,
        "description": (
            "The X-Powered-By header exposes the backend framework or "
            "language in use, helping attackers select targeted exploits."
        ),
        "remediation": "Remove the X-Powered-By header from responses.",
    },
    "X-AspNet-Version": {
        "severity": Severity.LOW,
        "cvss": 2.6,
        "description": (
            "The X-AspNet-Version header discloses the exact ASP.NET "
            "version, enabling attackers to find known vulnerabilities."
        ),
        "remediation": (
            "Remove the X-AspNet-Version header by adding "
            "'<httpRuntime enableVersionHeader=\"false\" />' to web.config."
        ),
    },
}


class HeaderAnalyzerPlugin(ScannerPlugin):
    """Analyzes HTTP response headers for security issues."""

    name = "header-analyzer"
    description = "Checks for missing security headers and info-leaking headers"
    version = "1.0.0"
    stage = "scan"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.include_legacy_headers = bool(self.config.get("include_legacy_headers", False))

    def _resolve_url(self, target: Target) -> str:
        """Build the URL to scan from the target."""
        if target.url:
            return target.url
        scheme = "https" if target.port in (443, 8443) else "http"
        port_part = "" if target.port in (80, 443, None) else f":{target.port}"
        host = target.domain or target.ip or target.host
        return f"{scheme}://{host}{port_part}"

    @staticmethod
    def _is_https_url(url: str) -> bool:
        return urlparse(url).scheme.lower() == "https"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = self._resolve_url(target)
        is_https = self._is_https_url(url)

        # Skip if we've already analyzed this exact URL in a prior run
        prior_findings = kwargs.get("findings", [])
        already_analyzed = any(
            f.module_name == self.name and f.metadata.get("url") == url
            for f in prior_findings
        )
        if already_analyzed:
            logger.debug(f"[header-analyzer] Already analyzed {url}, skipping")
            return findings

        try:
            async with self.create_http_client() as client:
                response = await client.get(
                    url,
                    headers=self.get_request_headers(),
                )
        except httpx.RequestError as exc:
            logger.warning(f"[header-analyzer] Request to {url} failed: {exc}")
            return findings

        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        logger.debug(
            f"[header-analyzer] Got {response.status_code} from {url} "
            f"with {len(resp_headers)} headers"
        )

        # Check for missing security headers
        for header_name, meta in SECURITY_HEADERS.items():
            if header_name == "Strict-Transport-Security" and not is_https:
                continue
            if header_name == "X-XSS-Protection" and not self.include_legacy_headers:
                continue
            if header_name.lower() not in resp_headers:
                findings.append(
                    Finding(
                        title=f"Missing Security Header: {header_name}",
                        description=meta["description"],
                        severity=meta["severity"],
                        finding_state=FindingState.SUSPECTED,
                        confidence_score=0.9 if header_name != "Content-Security-Policy" else 0.75,
                        cvss_score=meta["cvss"],
                        category="security-headers",
                        evidence=f"Header '{header_name}' absent in response from {url}",
                        remediation=meta["remediation"],
                        references=meta.get("references", []),
                        metadata={"url": url, "status_code": response.status_code},
                    )
                )

        # Check for information-leaking headers
        for header_name, meta in INFO_LEAK_HEADERS.items():
            header_lower = header_name.lower()
            if header_lower in resp_headers:
                value = resp_headers[header_lower]
                findings.append(
                    Finding(
                        title=f"Information Disclosure: {header_name}",
                        description=meta["description"],
                        severity=meta["severity"],
                        finding_state=FindingState.INFO,
                        confidence_score=0.98,
                        cvss_score=meta["cvss"],
                        category="information-disclosure",
                        evidence=f"{header_name}: {value}",
                        remediation=meta["remediation"],
                        metadata={
                            "url": url,
                            "header_name": header_name,
                            "header_value": value,
                        },
                    )
                )

        return findings
