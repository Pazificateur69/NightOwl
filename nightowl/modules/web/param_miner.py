"""Hidden parameter discovery - like Burp Param Miner but free."""

import logging
from urllib.parse import urlencode, urlparse, urlunparse

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target
from nightowl.utils.web_discovery import discover_web_attack_surface

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
    config_schema = {
        "discovery_depth": (int, 1),
        "discovery_max_pages": (int, 6),
        "discovery_max_urls": (int, 12),
        "max_candidate_urls": (int, 8),
        "param_wordlist": (list, PARAM_WORDLIST),
        "test_values": (list, ["1", "true", "admin", "../etc/passwd"]),
    }

    @staticmethod
    def _default_form_value(param_name: str) -> str:
        lowered = param_name.lower()
        if lowered in {"id", "page", "limit", "offset"}:
            return "1"
        return "test"

    @staticmethod
    def _append_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        separator = "&" if parsed.query else "?"
        return f"{url}{separator}{urlencode({param: value})}"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"

        try:
            async with self.create_http_client() as client:
                # Get baseline response
                baseline = await client.get(url, headers=self.get_request_headers())
                discovery = await discover_web_attack_surface(
                    client,
                    str(baseline.url),
                    default_value_fn=self._default_form_value,
                    max_depth=self.config.get("discovery_depth", 1),
                    max_pages=self.config.get("discovery_max_pages", 6),
                    max_urls_with_params=self.config.get("discovery_max_urls", 12),
                    request_headers=self.get_request_headers(),
                    wait_hook=self.wait_request_delay,
                )
                candidate_urls = [str(baseline.url)]
                for discovered_url in discovery.urls_with_params:
                    if discovered_url not in candidate_urls:
                        candidate_urls.append(discovered_url)
                candidate_urls = candidate_urls[: self.config.get("max_candidate_urls", 8)]
                param_wordlist = self.config.get("param_wordlist", PARAM_WORDLIST)
                test_values = self.config.get("test_values", ["1", "true", "admin", "../etc/passwd"])

                discovered = []

                for candidate_url in candidate_urls:
                    try:
                        candidate_baseline = await client.get(candidate_url, headers=self.get_request_headers())
                    except Exception as exc:
                        logger.debug(f"Suppressed error: {exc}")
                        await self.wait_request_delay()
                        continue

                    baseline_len = len(candidate_baseline.content)
                    baseline_status = candidate_baseline.status_code
                    baseline_headers = set(candidate_baseline.headers.keys())

                    for param in param_wordlist:
                        for value in test_values:
                            test_url = self._append_param(candidate_url, param, value)
                            try:
                                resp = await client.get(test_url, headers=self.get_request_headers())

                                diff_len = abs(len(resp.content) - baseline_len)
                                new_headers = set(resp.headers.keys()) - baseline_headers
                                status_changed = resp.status_code != baseline_status

                                is_interesting = (
                                    diff_len > 50
                                    or new_headers
                                    or status_changed
                                    or resp.status_code in (500, 403, 401)
                                )
                                if resp.status_code == 404:
                                    is_interesting = False

                                if is_interesting:
                                    discovered.append({
                                        "base_url": candidate_url,
                                        "param": param,
                                        "value": value,
                                        "status": resp.status_code,
                                        "size_diff": diff_len,
                                        "new_headers": list(new_headers),
                                    })
                                    break

                            except (OSError, RuntimeError, ValueError, Exception) as exc:
                                logger.debug(f"Suppressed error: {exc}")
                                continue
                            finally:
                                await self.wait_request_delay()

                for d in discovered:
                    sev = Severity.MEDIUM
                    if d["status"] in (500, 403) or d["param"] in ("debug", "admin", "cmd", "exec"):
                        sev = Severity.HIGH

                    findings.append(Finding(
                        title=f"Hidden parameter: {d['param']}={d['value']}",
                        severity=sev,
                        description=f"Parameter '{d['param']}' changes server behavior",
                        evidence=(
                            f"Base URL: {d['base_url']}\n"
                            f"Test URL: {self._append_param(d['base_url'], d['param'], d['value'])}\n"
                            f"Status: {d['status']}\n"
                            f"Size diff: {d['size_diff']} bytes\n"
                            f"New headers: {d['new_headers']}"
                        ),
                        remediation="Review hidden parameters. Disable debug parameters in production.",
                        category="param-miner",
                    ))

        except Exception as e:
            logger.warning(f"Param miner failed: {e}")

        return findings
