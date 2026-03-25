"""Open redirect scanner plugin.

Tests URL parameters for open redirect vulnerabilities by injecting external
URLs and checking if the server redirects to them without validation.
"""

import logging
from urllib.parse import parse_qs, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# External domains used to detect open redirects
REDIRECT_TARGETS = [
    "https://evil.nightowl-test.com",
    "//evil.nightowl-test.com",
    "https://evil.nightowl-test.com/",
]

# Redirect payloads with various bypass techniques
REDIRECT_PAYLOADS: list[tuple[str, str]] = [
    # Standard external URLs
    ("https://evil.nightowl-test.com", "Direct HTTPS URL"),
    ("http://evil.nightowl-test.com", "Direct HTTP URL"),

    # Protocol-relative
    ("//evil.nightowl-test.com", "Protocol-relative URL"),
    ("///evil.nightowl-test.com", "Triple-slash"),

    # Backslash trick (some parsers treat \ as /)
    ("/\\evil.nightowl-test.com", "Backslash bypass"),
    ("\\evil.nightowl-test.com", "Leading backslash"),

    # URL encoding bypass
    ("https:%2F%2Fevil.nightowl-test.com", "URL-encoded slashes"),
    ("%2F%2Fevil.nightowl-test.com", "Encoded protocol-relative"),

    # Double encoding
    ("https:%252F%252Fevil.nightowl-test.com", "Double-encoded slashes"),

    # Tab/whitespace bypass
    ("https://evil.nightowl-test.com%09", "Tab character appended"),
    ("\thttps://evil.nightowl-test.com", "Leading tab"),

    # Null byte
    ("https://evil.nightowl-test.com%00", "Null byte appended"),

    # At-sign bypass: http://trusted.com@evil.com
    ("https://trusted.com@evil.nightowl-test.com", "Userinfo @ bypass"),

    # Dot bypass  (some validators check prefix only)
    ("https://evil.nightowl-test.com.trusted.com", "Subdomain disguise"),

    # javascript: URI scheme (for DOM-based redirects)
    ("javascript:alert(document.domain)", "JavaScript URI"),
    ("javascript://nightowl-test.com/%0aalert(1)", "JavaScript with comment"),

    # data: URI
    ("data:text/html,<script>alert(1)</script>", "Data URI"),

    # Carriage return / newline tricks
    ("https://evil.nightowl-test.com%0d%0a", "CRLF appended"),
]

# Parameter names commonly used for redirects
REDIRECT_PARAM_NAMES = [
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "uri",
    "next",
    "nextUrl",
    "next_url",
    "return",
    "returnTo",
    "return_to",
    "returnUrl",
    "return_url",
    "goto",
    "go",
    "dest",
    "destination",
    "rurl",
    "redir",
    "target",
    "forward",
    "forward_url",
    "continue",
    "callback",
    "callback_url",
    "path",
    "out",
    "view",
    "login",
    "logout",
    "image_url",
    "checkout_url",
]

# Redirect-related paths that often contain redirect params
REDIRECT_PATHS = [
    "/login",
    "/logout",
    "/signin",
    "/signout",
    "/auth",
    "/oauth",
    "/redirect",
    "/callback",
    "/sso",
    "/saml",
]


class OpenRedirectPlugin(ScannerPlugin):
    name = "open-redirect"
    description = "Test for open redirect vulnerabilities"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        params = parse_qs(parsed.query)
        target_domain = parsed.netloc.lower()

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=False, timeout=10
            ) as client:
                confirmed_params: set[str] = set()

                # ── Phase 1: Test existing URL parameters ──
                test_params = dict(params)

                # Identify redirect-like params from existing query string
                redirect_params = {
                    k: v for k, v in test_params.items()
                    if k.lower() in {p.lower() for p in REDIRECT_PARAM_NAMES}
                }

                # If no redirect-like params, add common ones
                if not redirect_params:
                    redirect_params = {
                        p: ["test"] for p in REDIRECT_PARAM_NAMES[:10]
                    }

                for param_name in redirect_params:
                    if param_name in confirmed_params:
                        continue

                    for payload, payload_desc in REDIRECT_PAYLOADS:
                        if param_name in confirmed_params:
                            break

                        # Build test URL preserving other params
                        qp = {
                            k: v[0] if isinstance(v, list) else v
                            for k, v in params.items()
                        }
                        qp[param_name] = payload
                        # Use manual query building for payloads with special chars
                        query_parts = []
                        for k, v in qp.items():
                            query_parts.append(f"{k}={v}")
                        test_url = urlunparse(
                            parsed._replace(query="&".join(query_parts))
                        )

                        try:
                            resp = await client.get(test_url)
                            finding = self._check_redirect(
                                resp, param_name, payload, payload_desc,
                                test_url, target_domain
                            )
                            if finding:
                                findings.append(finding)
                                confirmed_params.add(param_name)
                                break
                        except Exception:
                            continue

                # ── Phase 2: Test redirect-related paths ──
                for path in REDIRECT_PATHS:
                    endpoint = f"{base_url}{path}"
                    for param_name in ["next", "redirect", "url", "return"]:
                        if f"{path}:{param_name}" in confirmed_params:
                            continue

                        for payload, payload_desc in REDIRECT_PAYLOADS[:6]:
                            test_url = f"{endpoint}?{param_name}={payload}"
                            try:
                                resp = await client.get(test_url)
                                finding = self._check_redirect(
                                    resp, param_name, payload, payload_desc,
                                    test_url, target_domain
                                )
                                if finding:
                                    findings.append(finding)
                                    confirmed_params.add(f"{path}:{param_name}")
                                    break
                            except Exception:
                                continue

                # ── Phase 3: Test POST-based redirects ──
                for param_name in ["next", "redirect", "url", "return_url"]:
                    if f"post:{param_name}" in confirmed_params:
                        continue

                    payload = "https://evil.nightowl-test.com"
                    try:
                        resp = await client.post(url, data={param_name: payload})
                        finding = self._check_redirect(
                            resp, param_name, payload, "POST redirect",
                            url, target_domain
                        )
                        if finding:
                            finding.evidence += "\nMethod: POST"
                            findings.append(finding)
                            confirmed_params.add(f"post:{param_name}")
                    except Exception:
                        continue

        except Exception as e:
            logger.warning(f"Open redirect scan failed: {e}")

        return findings

    def _check_redirect(
        self,
        resp: httpx.Response,
        param_name: str,
        payload: str,
        payload_desc: str,
        test_url: str,
        target_domain: str,
    ) -> Finding | None:
        """Check if the response redirects to the injected external domain."""
        # Check for redirect status codes
        if resp.status_code not in (301, 302, 303, 307, 308):
            # Also check for meta refresh or JavaScript redirects
            body_lower = resp.text.lower()
            if "evil.nightowl-test.com" in body_lower:
                # Check for meta refresh
                if 'http-equiv="refresh"' in body_lower or "window.location" in body_lower:
                    return Finding(
                        title=f"Client-Side Open Redirect via '{param_name}'",
                        severity=Severity.MEDIUM,
                        cvss_score=4.7,
                        description=(
                            f"Parameter '{param_name}' is reflected in a client-side redirect "
                            f"(meta refresh or JavaScript). Bypass: {payload_desc}."
                        ),
                        evidence=(
                            f"URL: {test_url}\n"
                            f"Parameter: {param_name}\n"
                            f"Payload: {payload}\n"
                            f"Type: Client-side redirect"
                        ),
                        remediation=(
                            "Validate redirect targets server-side. Use allowlists of permitted domains. "
                            "Avoid reflecting user input in meta refresh tags or JavaScript redirects."
                        ),
                        category="open-redirect",
                    )
            return None

        # Check Location header
        location = resp.headers.get("location", "")
        if not location:
            return None

        location_lower = location.lower()
        location_parsed = urlparse(location)
        location_host = location_parsed.netloc.lower() or ""

        # Determine if redirect points to external domain
        is_external = False

        if "evil.nightowl-test.com" in location_lower:
            is_external = True
        elif location_host and location_host != target_domain:
            # Check if it's not a subdomain of the target
            if not location_host.endswith(f".{target_domain}"):
                is_external = True
        elif location.startswith("//") and "evil.nightowl-test.com" in location:
            is_external = True
        elif location.startswith("javascript:"):
            return Finding(
                title=f"JavaScript URI Injection via '{param_name}'",
                severity=Severity.MEDIUM,
                cvss_score=4.7,
                description=(
                    f"Parameter '{param_name}' allows JavaScript URI injection in redirects."
                ),
                evidence=(
                    f"URL: {test_url}\n"
                    f"Parameter: {param_name}\n"
                    f"Location: {location[:200]}"
                ),
                remediation="Block javascript: and data: URI schemes in redirect targets.",
                category="open-redirect",
            )

        if is_external:
            return Finding(
                title=f"Open Redirect via '{param_name}'",
                severity=Severity.MEDIUM,
                cvss_score=4.7,
                description=(
                    f"Open redirect in parameter '{param_name}'. "
                    f"Bypass technique: {payload_desc}. "
                    "An attacker can redirect users to malicious sites for phishing, "
                    "credential theft, or malware distribution."
                ),
                evidence=(
                    f"URL: {test_url}\n"
                    f"Parameter: {param_name}\n"
                    f"Payload: {payload}\n"
                    f"Location header: {location[:200]}\n"
                    f"Status: {resp.status_code}"
                ),
                remediation=(
                    "Validate redirect destinations against an allowlist of trusted domains. "
                    "Use relative paths instead of full URLs. "
                    "Implement a redirect warning page for external redirects."
                ),
                category="open-redirect",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/601.html",
                ],
                metadata={
                    "bypass_technique": payload_desc,
                    "redirect_target": location[:200],
                },
            )

        return None
