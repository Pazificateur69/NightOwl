"""Authentication tester plugin - default credentials check."""

import asyncio
import logging

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target
from nightowl.utils.web_auth import DEFAULT_LOGIN_PATHS, extract_login_form, login_successful, submit_login_form

logger = logging.getLogger("nightowl")

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("administrator", "administrator"), ("test", "test"),
    ("user", "user"), ("guest", "guest"), ("admin", ""),
]

class AuthTesterPlugin(ScannerPlugin):
    name = "auth-tester"
    description = "Test for default credentials on login forms"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = (target.url or f"https://{target.host}").rstrip("/")
        delay = self.config.get("delay", 1.0)
        credentials = self.auth_config.get("default_credentials", DEFAULT_CREDS)
        max_attempts = int(self.auth_config.get("max_default_credential_attempts", 5) or 5)

        try:
            async with self.create_http_client() as client:
                for path in DEFAULT_LOGIN_PATHS:
                    url = f"{base_url}{path}"
                    try:
                        resp = await client.get(url, headers=self.get_request_headers())
                        if resp.status_code != 200:
                            continue

                        form = extract_login_form(resp.text, str(resp.url), auth_config=self.auth_config)
                        if not form:
                            continue

                        # Test default creds
                        for username, password in credentials[:max_attempts]:
                            login_resp = await submit_login_form(
                                client,
                                form,
                                username,
                                password,
                                headers=self.get_request_headers(),
                                auth_config=self.auth_config,
                            )

                            if login_successful(login_resp, self.auth_config):
                                findings.append(Finding(
                                    title=f"Default credentials work: {username}:{password}",
                                    severity=Severity.CRITICAL, cvss_score=9.8,
                                    description=f"Login with default credentials succeeded at {url}",
                                    evidence=f"URL: {url}\nUsername: {username}\nPassword: {password}\nResponse: {login_resp.status_code}",
                                    remediation="Change all default credentials. Enforce strong password policies.",
                                    category="authentication",
                                ))
                                break

                            await asyncio.sleep(delay)

                    except Exception as e:
                        logger.debug(f"Auth test failed for {url}: {e}")

        except Exception as e:
            logger.warning(f"Auth tester failed: {e}")

        return findings
