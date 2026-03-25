"""Authentication tester plugin - default credentials check."""

import asyncio
import logging

import httpx
from bs4 import BeautifulSoup

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("administrator", "administrator"), ("test", "test"),
    ("user", "user"), ("guest", "guest"), ("admin", ""),
]

LOGIN_PATHS = ["/login", "/admin", "/wp-login.php", "/administrator", "/auth/login", "/signin", "/user/login"]


class AuthTesterPlugin(ScannerPlugin):
    name = "auth-tester"
    description = "Test for default credentials on login forms"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = (target.url or f"https://{target.host}").rstrip("/")
        delay = self.config.get("delay", 1.0)

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                for path in LOGIN_PATHS:
                    url = f"{base_url}{path}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            continue

                        soup = BeautifulSoup(resp.text, "html.parser")
                        form = soup.find("form")
                        if not form:
                            continue

                        # Find username and password fields
                        inputs = form.find_all("input")
                        user_field = None
                        pass_field = None
                        for inp in inputs:
                            t = inp.get("type", "").lower()
                            n = inp.get("name", "").lower()
                            if t == "password" or "pass" in n:
                                pass_field = inp.get("name")
                            elif t in ("text", "email") or any(k in n for k in ("user", "email", "login", "name")):
                                user_field = inp.get("name")

                        if not user_field or not pass_field:
                            continue

                        action = form.get("action", path)
                        if not action.startswith("http"):
                            action = f"{base_url}{action}"

                        # Test default creds
                        for username, password in DEFAULT_CREDS[:5]:  # limit attempts
                            data = {user_field: username, pass_field: password}
                            # Grab CSRF tokens
                            for inp in inputs:
                                if inp.get("type") == "hidden" and inp.get("name") and inp.get("value"):
                                    data[inp["name"]] = inp["value"]

                            login_resp = await client.post(action, data=data)

                            # Heuristic: login success if redirect to dashboard or no "invalid" in response
                            is_success = (
                                login_resp.status_code in (301, 302, 303)
                                or ("dashboard" in login_resp.headers.get("location", "").lower())
                                or ("invalid" not in login_resp.text.lower() and "error" not in login_resp.text.lower() and "failed" not in login_resp.text.lower())
                            )

                            if is_success and login_resp.status_code != 200:
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
