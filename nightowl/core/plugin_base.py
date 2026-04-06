"""Abstract base class for all NightOwl scanner plugins."""

import asyncio
import logging
import time
from abc import ABC, abstractmethod

import httpx

from nightowl.modules import get_module_maturity, is_core_module
from nightowl.models.finding import Finding
from nightowl.models.target import Target
from nightowl.utils.rate_limiter import get_global_limiter
from nightowl.utils.web_auth import bootstrap_login_from_config

logger = logging.getLogger("nightowl")


class ScannerPlugin(ABC):
    """Base class that all scanner modules must implement."""

    name: str = "base-plugin"
    description: str = ""
    author: str = "NightOwl"
    version: str = "1.0.0"
    stage: str = "scan"  # recon, scan, exploit, post

    # Subclasses can define expected config keys with defaults
    config_schema: dict[str, type | tuple] = {}

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.findings: list[Finding] = []
        self._is_setup = False
        rate_limit = self.config.get("rate_limit", {}) or {}
        self.timeout: float = float(self.config.get("timeout", 30))
        self.user_agent: str = self.config.get("user_agent", "NightOwl/1.0")
        self.follow_redirects: bool = self.config.get("follow_redirects", True)
        self.verify_ssl: bool = self.config.get("verify_ssl", False)
        self.proxy: str | None = self.config.get("proxy")
        self.default_headers: dict = self.config.get("headers", {}) or {}
        self.default_cookies: dict = self.config.get("cookies", {}) or {}
        self.auth_config: dict = self.config.get("auth", {}) or {}
        self.request_delay: float = float(rate_limit.get("delay_between_requests", 0.0))
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate config against schema and apply defaults for missing keys."""
        for key, type_or_default in self.config_schema.items():
            if isinstance(type_or_default, tuple):
                expected_type, default_value = type_or_default
            else:
                expected_type = type_or_default
                default_value = None

            if key not in self.config:
                if default_value is not None:
                    self.config[key] = default_value
                    logger.debug(f"[{self.name}] Config key '{key}' missing, using default: {default_value}")
            elif not isinstance(self.config[key], expected_type):
                logger.warning(
                    f"[{self.name}] Config key '{key}' has wrong type "
                    f"(expected {expected_type.__name__}, got {type(self.config[key]).__name__}), "
                    f"using default"
                )
                if default_value is not None:
                    self.config[key] = default_value

    async def setup(self) -> None:
        """Optional setup before scanning. Override if needed."""
        pass

    @abstractmethod
    async def run(self, target: Target, **kwargs) -> list[Finding]:
        """Execute the scan against a target. Must be implemented."""
        ...

    async def teardown(self) -> None:
        """Optional cleanup after scanning. Override if needed."""
        pass

    def get_request_headers(self, extra_headers: dict | None = None) -> dict:
        headers = {"User-Agent": self.user_agent}
        headers.update(self.default_headers)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def create_http_client(self, **overrides) -> httpx.AsyncClient:
        client_kwargs = {
            "verify": self.verify_ssl,
            "follow_redirects": self.follow_redirects,
            "timeout": self.timeout,
            "headers": self.get_request_headers(),
        }
        if self.proxy:
            client_kwargs["proxy"] = self.proxy
        if self.default_cookies:
            client_kwargs["cookies"] = self.default_cookies
        client_kwargs.update(overrides)
        return httpx.AsyncClient(**client_kwargs)

    async def wait_request_delay(self) -> None:
        """Wait for per-module delay AND acquire a global rate limiter token."""
        limiter = get_global_limiter()
        await limiter.acquire()
        limiter.release()
        if self.request_delay > 0:
            await asyncio.sleep(self.request_delay)

    async def bootstrap_auth(self, client: httpx.AsyncClient) -> httpx.Response | None:
        """Optionally authenticate the shared HTTP client using config.auth."""
        if not self.auth_config:
            return None
        try:
            return await bootstrap_login_from_config(
                client,
                self.auth_config,
                headers=self.get_request_headers(),
            )
        except Exception as exc:
            logger.debug(f"[{self.name}] auth bootstrap failed: {exc}")
            return None

    async def execute(self, target: Target, **kwargs) -> list[Finding]:
        """Full lifecycle: setup -> run -> teardown. Raises on failure."""
        start = time.time()
        self._last_error: str | None = None
        try:
            if not self._is_setup:
                await self.setup()
                self._is_setup = True

            logger.info(f"[{self.name}] Scanning {target.host}...")
            findings = await self.run(target, **kwargs)

            # Validate and enrich findings
            allowed_hosts = {target.host, target.effective_host}
            if target.ip:
                allowed_hosts.add(target.ip)
            if target.domain:
                allowed_hosts.add(target.domain)

            validated_findings = []
            for f in findings:
                f.module_name = self.name
                f.target = target.host
                f.metadata.setdefault("module_maturity", get_module_maturity(self.name))
                f.metadata.setdefault("core_module", is_core_module(self.name))

                # Check for out-of-scope data leaks in evidence/metadata
                evidence_lower = f.evidence.lower()
                has_leak = False
                for key, val in f.metadata.items():
                    if isinstance(val, str) and "://" in val:
                        # Extract hostname from URLs in metadata
                        try:
                            from urllib.parse import urlparse as _parse_url
                            parsed_host = _parse_url(val).hostname
                            if parsed_host and parsed_host not in allowed_hosts:
                                logger.warning(
                                    f"[{self.name}] Finding references out-of-scope "
                                    f"host '{parsed_host}' in metadata key '{key}' — stripped"
                                )
                                f.metadata[key] = "[REDACTED-OUT-OF-SCOPE]"
                                has_leak = True
                        except Exception:
                            pass

                validated_findings.append(f)

            self.findings.extend(validated_findings)
            elapsed = time.time() - start
            logger.info(f"[{self.name}] Found {len(validated_findings)} findings in {elapsed:.1f}s")
            return validated_findings

        except Exception as e:
            elapsed = time.time() - start
            self._last_error = str(e)
            logger.error(f"[{self.name}] FAILED after {elapsed:.1f}s: {e}")
            raise

        finally:
            try:
                await self.teardown()
            except Exception as e:
                logger.warning(f"[{self.name}] Teardown error: {e}")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} stage={self.stage}>"
