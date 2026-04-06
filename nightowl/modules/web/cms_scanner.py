"""CMS detection and fingerprinting plugin.

Detects non-WordPress content management systems including Drupal,
Joomla, Magento, Shopify, Ghost, and Laravel. Checks for version
exposure and default admin panel accessibility.
"""

import logging
import re

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")


class CMSScannerPlugin(ScannerPlugin):
    """Detect CMS platforms and common misconfigurations."""

    name = "cms-scanner"
    description = (
        "Detect CMS type (Drupal, Joomla, Magento, Shopify, Ghost, Laravel), "
        "enumerate versions, and check for exposed admin panels and config files"
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
                # Fetch main page once and reuse
                try:
                    main_resp = await client.get(base_url)
                    main_body = main_resp.text
                    main_headers = {
                        k.lower(): v for k, v in main_resp.headers.items()
                    }
                except httpx.RequestError as exc:
                    logger.warning(f"[{self.name}] Cannot reach {base_url}: {exc}")
                    return findings

                # Run detection for each CMS
                drupal = await self._detect_drupal(client, base_url, main_body, main_headers)
                findings.extend(drupal)

                joomla = await self._detect_joomla(client, base_url, main_body, main_headers)
                findings.extend(joomla)

                magento = await self._detect_magento(client, base_url, main_body, main_headers)
                findings.extend(magento)

                shopify = self._detect_shopify(base_url, main_body, main_headers)
                findings.extend(shopify)

                ghost = await self._detect_ghost(client, base_url, main_body, main_headers)
                findings.extend(ghost)

                laravel = await self._detect_laravel(client, base_url, main_body, main_headers)
                findings.extend(laravel)

        except Exception as e:
            logger.error(f"[{self.name}] {e}")

        return findings

    # ------------------------------------------------------------------
    # Drupal
    # ------------------------------------------------------------------
    async def _detect_drupal(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        body: str,
        headers: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        indicators: list[str] = []
        version: str | None = None

        # X-Generator header
        generator = headers.get("x-generator", "")
        if "drupal" in generator.lower():
            indicators.append(f"X-Generator header: {generator}")
            match = re.search(r"Drupal\s+([\d.]+)", generator, re.IGNORECASE)
            if match:
                version = match.group(1)

        # Drupal.js reference in body
        if "/misc/drupal.js" in body or "/core/misc/drupal.js" in body:
            indicators.append("drupal.js reference in page source")

        # Meta generator tag
        match = re.search(
            r'<meta\s+name=["\']Generator["\']\s+content=["\']Drupal\s*([\d.]*)',
            body,
            re.IGNORECASE,
        )
        if match:
            indicators.append("Drupal meta generator tag")
            if match.group(1) and not version:
                version = match.group(1)

        # CHANGELOG.txt (Drupal 7)
        try:
            resp = await client.get(f"{base_url}/CHANGELOG.txt")
            if resp.status_code == 200 and "drupal" in resp.text.lower():
                indicators.append("CHANGELOG.txt accessible")
                match = re.search(r"Drupal\s+([\d.]+)", resp.text)
                if match and not version:
                    version = match.group(1)
                findings.append(Finding(
                    title="Drupal CHANGELOG.txt exposed",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description="Drupal CHANGELOG.txt is publicly accessible, disclosing version history.",
                    evidence=f"URL: {base_url}/CHANGELOG.txt",
                    remediation="Restrict access to CHANGELOG.txt via web server configuration.",
                    category="cms-config-exposure",
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # /core/CHANGELOG.txt (Drupal 8+)
        try:
            resp = await client.get(f"{base_url}/core/CHANGELOG.txt")
            if resp.status_code == 200 and "drupal" in resp.text.lower():
                indicators.append("core/CHANGELOG.txt accessible (Drupal 8+)")
                match = re.search(r"Drupal\s+([\d.]+)", resp.text)
                if match and not version:
                    version = match.group(1)
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        if indicators:
            version_str = f" version {version}" if version else ""
            findings.append(Finding(
                title=f"Drupal CMS detected{version_str}",
                severity=Severity.INFO,
                description=f"Drupal{version_str} has been identified on this target.",
                evidence="\n".join(indicators),
                category="cms-detection",
                metadata={"cms": "drupal", "version": version},
            ))

        return findings

    # ------------------------------------------------------------------
    # Joomla
    # ------------------------------------------------------------------
    async def _detect_joomla(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        body: str,
        headers: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        indicators: list[str] = []
        version: str | None = None

        # Meta generator
        match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla[!\s]*([\d.]*)',
            body,
            re.IGNORECASE,
        )
        if match:
            indicators.append("Joomla meta generator tag")
            if match.group(1):
                version = match.group(1)

        # /media/system/js/ directory
        if "/media/system/js/" in body:
            indicators.append("Joomla /media/system/js/ reference in page source")

        # /administrator/ login page
        try:
            resp = await client.get(f"{base_url}/administrator/")
            if resp.status_code == 200 and ("joomla" in resp.text.lower() or "com_login" in resp.text.lower()):
                indicators.append("Joomla /administrator/ panel accessible")
                findings.append(Finding(
                    title="Joomla admin panel publicly accessible",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description="The Joomla administrator panel is accessible without IP restriction.",
                    evidence=f"URL: {base_url}/administrator/ returns HTTP 200",
                    remediation="Restrict access to /administrator/ by IP whitelist or .htaccess rules.",
                    category="cms-admin-exposure",
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # /administrator/manifests/files/joomla.xml for version
        try:
            resp = await client.get(f"{base_url}/administrator/manifests/files/joomla.xml")
            if resp.status_code == 200:
                match = re.search(r"<version>([\d.]+)</version>", resp.text)
                if match:
                    version = match.group(1)
                    indicators.append(f"Version from joomla.xml: {version}")
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        if indicators:
            version_str = f" version {version}" if version else ""
            findings.append(Finding(
                title=f"Joomla CMS detected{version_str}",
                severity=Severity.INFO,
                description=f"Joomla{version_str} has been identified on this target.",
                evidence="\n".join(indicators),
                category="cms-detection",
                metadata={"cms": "joomla", "version": version},
            ))

        return findings

    # ------------------------------------------------------------------
    # Magento
    # ------------------------------------------------------------------
    async def _detect_magento(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        body: str,
        headers: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        indicators: list[str] = []

        # /skin/frontend reference (Magento 1)
        if "/skin/frontend" in body:
            indicators.append("Magento 1 /skin/frontend reference in source")

        # /static/frontend (Magento 2)
        if "/static/frontend" in body or "/static/version" in body:
            indicators.append("Magento 2 /static/frontend reference in source")

        # Mage cookie
        set_cookie = headers.get("set-cookie", "")
        if "mage-" in set_cookie.lower() or "MAGE_" in set_cookie:
            indicators.append(f"Magento cookie detected in Set-Cookie header")

        # /downloader/ (Magento Connect, Magento 1)
        try:
            resp = await client.get(f"{base_url}/downloader/")
            if resp.status_code == 200 and "magento" in resp.text.lower():
                indicators.append("Magento Connect /downloader/ accessible")
                findings.append(Finding(
                    title="Magento Connect Manager exposed",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    description=(
                        "The Magento Connect downloader is publicly accessible. "
                        "This can be used to install malicious extensions."
                    ),
                    evidence=f"URL: {base_url}/downloader/",
                    remediation="Remove or restrict access to the /downloader/ directory.",
                    category="cms-admin-exposure",
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # /magento_version exposed
        try:
            resp = await client.get(f"{base_url}/magento_version")
            if resp.status_code == 200 and "magento" in resp.text.lower():
                indicators.append(f"Magento version endpoint: {resp.text.strip()[:100]}")
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        if indicators:
            findings.append(Finding(
                title="Magento CMS detected",
                severity=Severity.INFO,
                description="Magento e-commerce platform has been identified on this target.",
                evidence="\n".join(indicators),
                category="cms-detection",
                metadata={"cms": "magento"},
            ))

        return findings

    # ------------------------------------------------------------------
    # Shopify
    # ------------------------------------------------------------------
    def _detect_shopify(
        self,
        base_url: str,
        body: str,
        headers: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        indicators: list[str] = []

        # X-ShopId header
        shop_id = headers.get("x-shopid", "")
        if shop_id:
            indicators.append(f"X-ShopId header: {shop_id}")

        # cdn.shopify.com in source
        if "cdn.shopify.com" in body:
            indicators.append("cdn.shopify.com reference in page source")

        # Shopify-specific meta
        if "shopify" in headers.get("x-sorting-hat-shopid", "").lower():
            indicators.append("X-Sorting-Hat-ShopId header present")

        # Powered by Shopify comment
        if "<!-- powered by shopify" in body.lower() or "shopify.com" in headers.get("link", ""):
            indicators.append("Shopify signature in HTML/headers")

        if indicators:
            findings.append(Finding(
                title="Shopify platform detected",
                severity=Severity.INFO,
                description="Target is hosted on the Shopify e-commerce platform.",
                evidence="\n".join(indicators),
                category="cms-detection",
                metadata={"cms": "shopify", "shop_id": shop_id or None},
            ))

        return findings

    # ------------------------------------------------------------------
    # Ghost
    # ------------------------------------------------------------------
    async def _detect_ghost(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        body: str,
        headers: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        indicators: list[str] = []

        # ghost-frontend in body
        if "ghost-frontend" in body.lower() or 'content="ghost' in body.lower():
            indicators.append("Ghost CMS reference in page source")

        # X-Ghost-Cache header
        if "x-ghost-cache" in headers:
            indicators.append(f"X-Ghost-Cache header present")

        # /ghost/ admin panel
        try:
            resp = await client.get(f"{base_url}/ghost/", follow_redirects=False)
            if resp.status_code in (200, 301, 302):
                location = resp.headers.get("location", "")
                if resp.status_code == 200 or "ghost" in location.lower():
                    indicators.append("Ghost admin panel /ghost/ accessible")
                    findings.append(Finding(
                        title="Ghost admin panel publicly accessible",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        description="The Ghost CMS admin panel is accessible without IP restriction.",
                        evidence=f"URL: {base_url}/ghost/ (HTTP {resp.status_code})",
                        remediation="Restrict access to /ghost/ admin by IP whitelist or reverse proxy rules.",
                        category="cms-admin-exposure",
                    ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Ghost API
        try:
            resp = await client.get(f"{base_url}/ghost/api/v4/admin/site/")
            if resp.status_code == 200:
                indicators.append("Ghost API /ghost/api/v4/admin/site/ accessible")
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        if indicators:
            findings.append(Finding(
                title="Ghost CMS detected",
                severity=Severity.INFO,
                description="Ghost CMS has been identified on this target.",
                evidence="\n".join(indicators),
                category="cms-detection",
                metadata={"cms": "ghost"},
            ))

        return findings

    # ------------------------------------------------------------------
    # Laravel
    # ------------------------------------------------------------------
    async def _detect_laravel(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        body: str,
        headers: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        indicators: list[str] = []

        # laravel_session cookie
        set_cookie = headers.get("set-cookie", "")
        if "laravel_session" in set_cookie:
            indicators.append("laravel_session cookie detected")

        # XSRF-TOKEN cookie (common in Laravel)
        if "xsrf-token" in set_cookie.lower():
            indicators.append("XSRF-TOKEN cookie detected (common in Laravel)")

        # Exposed .env file
        try:
            resp = await client.get(f"{base_url}/.env")
            if resp.status_code == 200:
                content = resp.text[:1000]
                if "APP_KEY=" in content or "DB_PASSWORD=" in content or "APP_ENV=" in content:
                    indicators.append(".env file is publicly accessible!")
                    findings.append(Finding(
                        title="Laravel .env file exposed",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        description=(
                            "The Laravel .env configuration file is publicly accessible. "
                            "It typically contains database credentials, API keys, "
                            "application secrets, and mail server credentials."
                        ),
                        evidence=f"URL: {base_url}/.env\nContains sensitive configuration keys",
                        remediation=(
                            "Block access to .env files in your web server configuration. "
                            "Rotate all credentials exposed in the file immediately."
                        ),
                        category="cms-config-exposure",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
                        ],
                    ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # /vendor/ directory exposure
        try:
            resp = await client.get(f"{base_url}/vendor/composer/installed.json")
            if resp.status_code == 200 and "packages" in resp.text.lower():
                indicators.append("Composer installed.json accessible")
                findings.append(Finding(
                    title="Laravel vendor/composer metadata exposed",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        "The Composer installed.json file is publicly accessible, "
                        "revealing all installed PHP packages and their versions."
                    ),
                    evidence=f"URL: {base_url}/vendor/composer/installed.json",
                    remediation="Block access to the /vendor/ directory in web server configuration.",
                    category="cms-config-exposure",
                ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        # Laravel debug page (Ignition)
        try:
            resp = await client.get(f"{base_url}/nonexistent-nightowl-test-404")
            if resp.status_code == 500 or resp.status_code == 404:
                if "laravel" in resp.text.lower() or "ignition" in resp.text.lower() or "whoops" in resp.text.lower():
                    indicators.append("Laravel debug/error page detected")
                    findings.append(Finding(
                        title="Laravel debug mode enabled",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description=(
                            "Laravel debug mode appears to be enabled in production, "
                            "exposing stack traces, environment variables, and database "
                            "queries in error responses."
                        ),
                        evidence=f"Error page contains Laravel/Ignition debug information",
                        remediation="Set APP_DEBUG=false in production .env and clear config cache.",
                        category="cms-config-exposure",
                    ))
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        if indicators:
            findings.append(Finding(
                title="Laravel framework detected",
                severity=Severity.INFO,
                description="Laravel PHP framework has been identified on this target.",
                evidence="\n".join(indicators),
                category="cms-detection",
                metadata={"cms": "laravel"},
            ))

        return findings
