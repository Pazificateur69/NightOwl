"""Hidden parameter discovery - like Burp Param Miner but free."""

import asyncio
import logging
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Common hidden parameters
PARAM_WORDLIST = [
    "debug", "test", "admin", "internal", "dev", "staging",
    "verbose", "trace", "log", "dump", "show_errors", "display_errors",
    "callback", "jsonp", "format", "output", "type", "mode",
    "action", "cmd", "command", "exec", "run", "do",
    "file", "path", "dir", "folder", "include", "require",
    "template", "tpl", "theme", "skin", "layout", "view",
    "redirect", "url", "next", "return", "goto", "dest",
    "user", "username", "email", "token", "key", "api_key",
    "secret", "password", "pass", "auth", "access_token",
    "id", "uid", "user_id", "account", "role", "privilege",
    "page", "limit", "offset", "sort", "order", "filter",
    "lang", "language", "locale", "region", "country",
    "source", "ref", "utm_source", "utm_campaign",
    "proxy", "host", "origin", "x-forwarded-for", "x-forwarded-host",
    "_method", "_token", "csrf", "nonce",
    "v", "version", "api_version",
    "cache", "no_cache", "bypass", "override",
    "config", "settings", "options", "env", "environment",
]


class ParamMinerPlugin(ScannerPlugin):
    name = "param-miner"
    description = "Discover hidden HTTP parameters that change server behavior"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                # Get baseline response
                baseline = await client.get(url)
                baseline_len = len(baseline.content)
                baseline_status = baseline.status_code
                baseline_headers = set(baseline.headers.keys())

                discovered = []

                for param in PARAM_WORDLIST:
                    for value in ["1", "true", "admin", "../etc/passwd"]:
                        test_url = f"{url}{'&' if '?' in url else '?'}{param}={value}"
                        try:
                            resp = await client.get(test_url)

                            # Detect differences
                            diff_len = abs(len(resp.content) - baseline_len)
                            new_headers = set(resp.headers.keys()) - baseline_headers
                            status_changed = resp.status_code != baseline_status

                            is_interesting = (
                                diff_len > 50
                                or new_headers
                                or status_changed
                                or resp.status_code in (500, 403, 401)
                            )

                            if is_interesting:
                                discovered.append({
                                    "param": param,
                                    "value": value,
                                    "status": resp.status_code,
                                    "size_diff": diff_len,
                                    "new_headers": list(new_headers),
                                })
                                break  # found, skip other values

                        except Exception:
                            continue

                    await asyncio.sleep(0.05)

                for d in discovered:
                    sev = Severity.MEDIUM
                    if d["status"] in (500, 403) or d["param"] in ("debug", "admin", "cmd", "exec"):
                        sev = Severity.HIGH

                    findings.append(Finding(
                        title=f"Hidden parameter: {d['param']}={d['value']}",
                        severity=sev,
                        description=f"Parameter '{d['param']}' changes server behavior",
                        evidence=f"URL: {url}?{d['param']}={d['value']}\nStatus: {d['status']}\nSize diff: {d['size_diff']} bytes\nNew headers: {d['new_headers']}",
                        remediation="Review hidden parameters. Disable debug parameters in production.",
                        category="param-miner",
                    ))

        except Exception as e:
            logger.warning(f"Param miner failed: {e}")

        return findings
