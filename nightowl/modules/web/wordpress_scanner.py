"""WordPress detection and vulnerability scanner plugin.

Detects WordPress installations, enumerates users and versions,
and checks for common misconfigurations and vulnerable plugins.
"""

import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Common plugins known to have had critical vulnerabilities
VULNERABLE_PLUGINS = [
    "contact-form-7",
    "elementor",
    "woocommerce",
    "wordpress-seo",       # yoast-seo
    "akismet",
    "jetpack",
    "wp-file-manager",
    "duplicator",
    "really-simple-ssl",
]


class WordPressScannerPlugin(ScannerPlugin):
    """Detect WordPress installations and common security issues."""

    name = "wordpress-scanner"
    description = (
        "Detect WordPress sites, enumerate users/versions, check xmlrpc, "
        "debug.log exposure, vulnerable plugins, and directory listings"
    )
    version = "1.0.0"
    stage = "scan"

    def _resolve_base_url(self, target: Target) -> str:
        if target.url:
            return target.url.rstrip("/")
        scheme = "https" if target.port in (443, 8443, None) else "http"
        host = target.domain or target.ip or target.host
        port_part = "" if target.port in (80, 443, None) else f":{target.port}"
        return f"{scheme}://{host}{port_part}"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        base_url = self._resolve_base_url(target)

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=10
            ) as client:
                # Step 1: Detect WordPress
                is_wp, detection_evidence = await self._detect_wordpress(client, base_url)
                if not is_wp:
                    logger.info(f"[{self.name}] No WordPress detected at {base_url}")
                    return findings

                findings.append(Finding(
                    title=f"WordPress installation detected",
                    severity=Severity.INFO,
                    description="WordPress CMS has been identified on this target.",
                    evidence=detection_evidence,
                    category="wordpress",
                    metadata={"url": base_url},
                ))

                # Step 2: Version detection
                version_finding = await self._detect_version(client, base_url)
                if version_finding:
                    findings.append(version_finding)

                # Step 3: User enumeration
                user_findings = await self._enumerate_users(client, base_url)
                findings.extend(user_findings)

                # Step 4: XML-RPC check
                xmlrpc_finding = await self._check_xmlrpc(client, base_url)
                if xmlrpc_finding:
                    findings.append(xmlrpc_finding)

                # Step 5: Debug log exposure
                debug_finding = await self._check_debug_log(client, base_url)
                if debug_finding:
                    findings.append(debug_finding)

                # Step 6: Plugin enumeration
                plugin_findings = await self._check_plugins(client, base_url)
                findings.extend(plugin_findings)

                # Step 7: Uploads directory listing
                uploads_finding = await self._check_uploads_listing(client, base_url)
                if uploads_finding:
                    findings.append(uploads_finding)

        except Exception as e:
            logger.error(f"[{self.name}] {e}")

        return findings

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------
    async def _detect_wordpress(
        self, client: httpx.AsyncClient, base_url: str
    ) -> tuple[bool, str]:
        """Check multiple indicators to confirm WordPress."""
        indicators: list[str] = []

        # Check main page for wp-content references
        try:
            resp = await client.get(base_url)
            body = resp.text.lower()
            if "/wp-content/" in body:
                indicators.append("wp-content reference in page source")
            if "/wp-includes/" in body:
                indicators.append("wp-includes reference in page source")
            if 'name="generator" content="wordpress' in body:
                indicators.append("WordPress meta generator tag")
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check wp-login.php
        try:
            resp = await client.get(f"{base_url}/wp-login.php")
            if resp.status_code == 200 and "wp-login" in resp.text.lower():
                indicators.append("wp-login.php accessible (HTTP 200)")
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check wp-json REST API
        try:
            resp = await client.get(f"{base_url}/wp-json/wp/v2/")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "namespace" in str(data) or "routes" in str(data):
                        indicators.append("WP REST API /wp-json/wp/v2/ accessible")
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Check /wp-admin/ (may redirect to wp-login)
        try:
            resp = await client.get(f"{base_url}/wp-admin/", follow_redirects=False)
            if resp.status_code in (200, 301, 302, 403):
                if resp.status_code in (301, 302):
                    location = resp.headers.get("location", "")
                    if "wp-login" in location:
                        indicators.append("wp-admin redirects to wp-login")
                elif resp.status_code == 200:
                    indicators.append("wp-admin accessible (HTTP 200)")
                elif resp.status_code == 403:
                    indicators.append("wp-admin returns 403 (exists but forbidden)")
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        is_wp = len(indicators) >= 1
        return is_wp, "\n".join(indicators) if indicators else "No WordPress indicators"

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------
    async def _detect_version(
        self, client: httpx.AsyncClient, base_url: str
    ) -> Finding | None:
        """Attempt to determine the WordPress version."""
        version: str | None = None
        source = ""

        # Method 1: Meta generator tag on homepage
        try:
            resp = await client.get(base_url)
            match = re.search(
                r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)',
                resp.text,
                re.IGNORECASE,
            )
            if match:
                version = match.group(1)
                source = "meta generator tag"
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Method 2: RSS feed
        if not version:
            try:
                resp = await client.get(f"{base_url}/feed/")
                if resp.status_code == 200:
                    match = re.search(
                        r'<generator>https?://wordpress\.org/\?v=([\d.]+)',
                        resp.text,
                    )
                    if match:
                        version = match.group(1)
                        source = "RSS feed generator tag"
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")

        # Method 3: readme.html
        if not version:
            try:
                resp = await client.get(f"{base_url}/readme.html")
                if resp.status_code == 200:
                    match = re.search(
                        r'Version\s+([\d.]+)', resp.text, re.IGNORECASE
                    )
                    if match:
                        version = match.group(1)
                        source = "readme.html"
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")

        if version:
            return Finding(
                title=f"WordPress version detected: {version}",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description=(
                    f"WordPress version {version} identified via {source}. "
                    "Exposing the version helps attackers find known vulnerabilities."
                ),
                evidence=f"Version: {version}\nSource: {source}",
                remediation=(
                    "Remove the meta generator tag, restrict access to readme.html, "
                    "and keep WordPress updated to the latest version."
                ),
                category="wordpress",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                ],
                metadata={"version": version, "source": source},
            )
        return None

    # ------------------------------------------------------------------
    # User enumeration
    # ------------------------------------------------------------------
    async def _enumerate_users(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        """Enumerate WordPress users via REST API and author archives."""
        findings: list[Finding] = []
        users: list[dict] = []

        # Method 1: REST API /wp-json/wp/v2/users
        try:
            resp = await client.get(f"{base_url}/wp-json/wp/v2/users")
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for user in data:
                        users.append({
                            "id": user.get("id"),
                            "name": user.get("name", ""),
                            "slug": user.get("slug", ""),
                        })
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Method 2: Author ID enumeration (?author=N)
        if not users:
            for author_id in range(1, 11):
                try:
                    resp = await client.get(
                        f"{base_url}/?author={author_id}",
                        follow_redirects=True,
                    )
                    if resp.status_code == 200:
                        # Extract username from URL slug (e.g., /author/admin/)
                        url_str = str(resp.url)
                        match = re.search(r'/author/([^/]+)', url_str)
                        if match:
                            slug = match.group(1)
                            users.append({
                                "id": author_id,
                                "name": slug,
                                "slug": slug,
                            })
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

        if users:
            user_list = "\n".join(
                f"  ID={u['id']} slug={u['slug']} name={u.get('name', '')}"
                for u in users
            )
            findings.append(Finding(
                title=f"WordPress user enumeration: {len(users)} user(s) found",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                description=(
                    "WordPress user accounts can be enumerated, allowing attackers "
                    "to target specific users with brute-force or phishing attacks."
                ),
                evidence=f"Enumerated users:\n{user_list}",
                remediation=(
                    "Disable the WP REST API user endpoint via a plugin or custom filter. "
                    "Block author archive enumeration by redirecting /?author= queries."
                ),
                category="wordpress",
                metadata={"users": users},
            ))

        return findings

    # ------------------------------------------------------------------
    # XML-RPC
    # ------------------------------------------------------------------
    async def _check_xmlrpc(
        self, client: httpx.AsyncClient, base_url: str
    ) -> Finding | None:
        """Check if xmlrpc.php is enabled and listable."""
        try:
            xmlrpc_url = f"{base_url}/xmlrpc.php"
            payload = (
                '<?xml version="1.0"?>'
                "<methodCall>"
                "<methodName>system.listMethods</methodName>"
                "<params></params>"
                "</methodCall>"
            )
            resp = await client.post(
                xmlrpc_url,
                content=payload,
                headers={"Content-Type": "text/xml"},
            )
            if resp.status_code == 200 and "<methodResponse>" in resp.text:
                methods_count = resp.text.count("<value><string>")
                has_multicall = "system.multicall" in resp.text
                has_pingback = "pingback.ping" in resp.text

                severity = Severity.HIGH if has_multicall else Severity.MEDIUM
                cvss = 7.5 if has_multicall else 5.3

                evidence_parts = [
                    f"xmlrpc.php is accessible and responds to system.listMethods",
                    f"Methods exposed: ~{methods_count}",
                    f"system.multicall available: {has_multicall}",
                    f"pingback.ping available: {has_pingback}",
                ]

                return Finding(
                    title="WordPress XML-RPC enabled",
                    severity=severity,
                    cvss_score=cvss,
                    description=(
                        "WordPress XML-RPC interface is enabled. system.multicall can be "
                        "abused for credential brute-force amplification attacks, and "
                        "pingback.ping can be used for DDoS reflection and SSRF."
                    ),
                    evidence="\n".join(evidence_parts),
                    remediation=(
                        "Disable XML-RPC entirely if not needed, or block system.multicall "
                        "and pingback methods. Use a WAF rule or plugin to restrict access."
                    ),
                    category="wordpress",
                    references=[
                        "https://www.wordfence.com/blog/2015/10/should-you-disable-xml-rpc-on-wordpress/",
                    ],
                    metadata={"has_multicall": has_multicall, "has_pingback": has_pingback},
                )
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")
        return None

    # ------------------------------------------------------------------
    # Debug log
    # ------------------------------------------------------------------
    async def _check_debug_log(
        self, client: httpx.AsyncClient, base_url: str
    ) -> Finding | None:
        """Check for exposed wp-content/debug.log."""
        try:
            resp = await client.get(f"{base_url}/wp-content/debug.log")
            if resp.status_code == 200 and len(resp.text) > 50:
                # Verify it looks like a log file
                if "PHP" in resp.text or "Warning" in resp.text or "Error" in resp.text or "Notice" in resp.text:
                    snippet = resp.text[:500].replace("\n", "\\n")
                    return Finding(
                        title="WordPress debug.log exposed",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description=(
                            "The WordPress debug log is publicly accessible. It may contain "
                            "sensitive information including file paths, database queries, "
                            "plugin errors, and potentially credentials or tokens."
                        ),
                        evidence=f"URL: {base_url}/wp-content/debug.log\nSnippet: {snippet}",
                        remediation=(
                            "Remove the debug.log file and set WP_DEBUG_LOG to false in "
                            "wp-config.php, or restrict access via .htaccess / server config."
                        ),
                        category="wordpress",
                        metadata={"size_bytes": len(resp.content)},
                    )
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")
        return None

    # ------------------------------------------------------------------
    # Plugin enumeration
    # ------------------------------------------------------------------
    async def _check_plugins(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Finding]:
        """Check for common vulnerable plugins by requesting their readme.txt."""
        findings: list[Finding] = []

        for plugin_slug in VULNERABLE_PLUGINS:
            try:
                readme_url = f"{base_url}/wp-content/plugins/{plugin_slug}/readme.txt"
                resp = await client.get(readme_url)
                if resp.status_code == 200 and len(resp.text) > 50:
                    # Try to extract version from readme
                    version = None
                    match = re.search(
                        r"Stable tag:\s*([\d.]+)", resp.text, re.IGNORECASE
                    )
                    if match:
                        version = match.group(1)

                    version_str = f" (version {version})" if version else ""
                    findings.append(Finding(
                        title=f"WordPress plugin detected: {plugin_slug}{version_str}",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description=(
                            f"The plugin '{plugin_slug}' is installed{version_str}. "
                            "Its readme.txt is publicly accessible, disclosing plugin presence "
                            "and version which aids targeted attacks."
                        ),
                        evidence=f"URL: {readme_url}\nVersion: {version or 'unknown'}",
                        remediation=(
                            f"Ensure {plugin_slug} is updated to the latest version. "
                            "Restrict access to plugin readme.txt files via server config."
                        ),
                        category="wordpress-plugins",
                        metadata={"plugin": plugin_slug, "version": version},
                    ))
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return findings

    # ------------------------------------------------------------------
    # Uploads directory listing
    # ------------------------------------------------------------------
    async def _check_uploads_listing(
        self, client: httpx.AsyncClient, base_url: str
    ) -> Finding | None:
        """Check if wp-content/uploads has directory listing enabled."""
        try:
            resp = await client.get(f"{base_url}/wp-content/uploads/")
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                if "index of" in body_lower or "<title>directory listing" in body_lower or 'class="indexcolname"' in body_lower:
                    return Finding(
                        title="WordPress uploads directory listing enabled",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description=(
                            "The /wp-content/uploads/ directory has listing enabled, "
                            "allowing anyone to browse uploaded files which may include "
                            "sensitive documents or backups."
                        ),
                        evidence=f"URL: {base_url}/wp-content/uploads/ returns directory listing",
                        remediation=(
                            "Disable directory listing in your web server configuration. "
                            "Add 'Options -Indexes' to .htaccess or equivalent."
                        ),
                        category="wordpress",
                    )
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")
        return None
