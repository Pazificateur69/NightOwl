"""Directory bruteforce scanner plugin."""

import hashlib
import logging
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from nightowl.config.defaults import COMMON_DIRS
from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, FindingState, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

PUBLIC_DISCOVERY_PATHS = {
    "assets",
    "docs",
    "login",
    "media",
}
INTERESTING_DISCOVERY_PATHS = {
    "robots.txt",
    "security.txt",
    "humans.txt",
    "crossdomain.xml",
}
SENSITIVE_DISCOVERY_HINTS = (
    ".env",
    ".git",
    ".htaccess",
    ".htpasswd",
    "admin",
    "backup",
    "config",
    "db",
    "dump",
)
SENSITIVE_CONTENT_HINTS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private key",
    "aws_access_key_id",
)


class DirBruteforcePlugin(ScannerPlugin):
    name = "dir-bruteforce"
    description = "Discover hidden directories and files via bruteforce"
    version = "1.0.0"
    stage = "scan"

    @staticmethod
    def _classify_path(path: str, status_code: int) -> tuple[str, Severity, FindingState, float]:
        normalized = path.strip("/").lower()

        if normalized in PUBLIC_DISCOVERY_PATHS:
            return "public", Severity.INFO, FindingState.INFO, 0.4

        if normalized in INTERESTING_DISCOVERY_PATHS:
            severity = Severity.LOW if status_code in (200, 403) else Severity.INFO
            state = FindingState.SUSPECTED if status_code in (200, 403) else FindingState.INFO
            confidence = 0.72 if status_code in (200, 403) else 0.6
            return "interesting", severity, state, confidence

        if any(hint in normalized for hint in SENSITIVE_DISCOVERY_HINTS):
            severity = Severity.MEDIUM if status_code in (200, 403) else Severity.LOW
            state = FindingState.SUSPECTED
            confidence = 0.88 if status_code in (200, 403) else 0.76
            return "sensitive", severity, state, confidence

        severity = Severity.LOW if status_code == 200 else Severity.INFO
        state = FindingState.SUSPECTED if status_code == 200 else FindingState.INFO
        confidence = 0.78 if status_code == 200 else 0.6
        return "unknown", severity, state, confidence

    @staticmethod
    def _refine_classification(
        path: str,
        path_kind: str,
        severity: Severity,
        state: FindingState,
        confidence: float,
        *,
        status_code: int,
        headers: dict[str, Any] | None = None,
        body_preview: str = "",
    ) -> tuple[str, Severity, FindingState, float, str]:
        normalized = path.strip("/").lower()
        headers = headers or {}
        content_type = str(headers.get("content-type", "")).lower()
        location = str(headers.get("location", "")).lower()
        preview = body_preview.lower()

        # Redirects to login or public assets are usually low-signal discoverability.
        if status_code in (301, 302) and any(token in location for token in ("/login", "/assets", "/media")):
            return "public", Severity.INFO, FindingState.INFO, min(confidence, 0.35), "redirects to a common public route"

        # Plain-text or JSON exposure on sensitive routes is stronger than path naming alone.
        if path_kind in {"sensitive", "unknown"} and status_code == 200:
            if any(token in content_type for token in ("json", "xml", "text/plain", "yaml")):
                return path_kind, Severity.MEDIUM, FindingState.SUSPECTED, max(confidence, 0.9), f"served as {content_type or 'structured content'}"
            if any(hint in preview for hint in SENSITIVE_CONTENT_HINTS):
                return path_kind, Severity.MEDIUM, FindingState.SUSPECTED, max(confidence, 0.92), "response preview contains sensitive-looking keywords"

        # Generic HTML login/docs pages are usually benign discoverability.
        if path_kind in {"public", "unknown"} and status_code == 200 and "text/html" in content_type:
            if normalized in PUBLIC_DISCOVERY_PATHS:
                return "public", Severity.INFO, FindingState.INFO, min(confidence, 0.35), "served as generic HTML page"

        return path_kind, severity, state, confidence, ""

    @staticmethod
    def _looks_like_baseline(
        status_code: int,
        content_length: int,
        baseline_status: int | None,
        baseline_length: int | None,
        *,
        body_hash: str = "",
        baseline_body_hash: str = "",
    ) -> bool:
        if baseline_status is None or baseline_length is None:
            return False
        if status_code != baseline_status:
            return False
        # If we have body hashes, use exact comparison (most reliable)
        if body_hash and baseline_body_hash:
            return body_hash == baseline_body_hash
        # Tighter heuristic: 5% tolerance with minimum 16 bytes
        return abs(content_length - baseline_length) <= max(16, int(baseline_length * 0.05))

    @staticmethod
    def _normalize_base_url(url: str) -> str:
        parsed = urlsplit(url)
        clean_path = parsed.path.rstrip("/") or "/"
        return urlunsplit((parsed.scheme, parsed.netloc, clean_path, "", ""))

    @staticmethod
    def _body_hash(content: bytes) -> str:
        return hashlib.md5(content).hexdigest()

    def _load_wordlist(self) -> list[str]:
        """Load wordlist from config — supports list or file path."""
        wordlist_cfg = self.config.get("wordlist", None)
        if wordlist_cfg is None:
            return COMMON_DIRS
        if isinstance(wordlist_cfg, list):
            return wordlist_cfg
        # Treat as file path
        wordlist_path = Path(wordlist_cfg)
        if wordlist_path.is_file():
            lines = wordlist_path.read_text().splitlines()
            return [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        logger.warning(f"Wordlist file not found: {wordlist_cfg}, using defaults")
        return COMMON_DIRS

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        base_url = self._normalize_base_url((target.url or f"https://{target.host}"))
        wordlist = self._load_wordlist()
        baseline_status = None
        baseline_length = None
        baseline_hash = ""

        try:
            async with self.create_http_client(follow_redirects=False) as client:
                # Send two baseline requests with random paths to detect soft-404 patterns
                baseline_url = f"{base_url}/nightowl-{uuid.uuid4().hex}"
                baseline_url2 = f"{base_url}/nightowl-{uuid.uuid4().hex}"
                try:
                    baseline = await client.get(baseline_url, headers=self.get_request_headers())
                    baseline_status = baseline.status_code
                    baseline_length = len(baseline.content)
                    baseline_hash = self._body_hash(baseline.content)

                    # Verify with second request
                    baseline2 = await client.get(baseline_url2, headers=self.get_request_headers())
                    baseline2_hash = self._body_hash(baseline2.content)
                    # If two random 404s have different bodies, body hashing won't work
                    if baseline_hash != baseline2_hash:
                        baseline_hash = ""  # Disable hash-based comparison
                except (OSError, RuntimeError, ValueError, Exception) as exc:
                    logger.debug(f"Error: {exc}")
                    baseline_status = None
                    baseline_length = None

                for path in wordlist:
                    test_url = f"{base_url}/{path}"
                    try:
                        resp = await client.get(test_url, headers=self.get_request_headers())
                        resp_hash = self._body_hash(resp.content) if baseline_hash else ""
                        if self._looks_like_baseline(
                            resp.status_code,
                            len(resp.content),
                            baseline_status,
                            baseline_length,
                            body_hash=resp_hash,
                            baseline_body_hash=baseline_hash,
                        ):
                            await self.wait_request_delay()
                            continue
                        if resp.status_code in (200, 301, 302, 403):
                            path_kind, sev, state, confidence = self._classify_path(path, resp.status_code)
                            path_kind, sev, state, confidence, refinement = self._refine_classification(
                                path,
                                path_kind,
                                sev,
                                state,
                                confidence,
                                status_code=resp.status_code,
                                headers=dict(resp.headers),
                                body_preview=resp.text[:256],
                            )
                            content_type = resp.headers.get("content-type", "")
                            location = resp.headers.get("location", "")
                            description = f"{path_kind.capitalize()} path /{path} returned HTTP {resp.status_code}"
                            if refinement:
                                description += f" and {refinement}"
                            findings.append(Finding(
                                title=f"Discovered: /{path} ({resp.status_code})",
                                severity=sev,
                                finding_state=state,
                                confidence_score=confidence,
                                description=description,
                                evidence=(
                                    f"URL: {test_url}\n"
                                    f"Status: {resp.status_code}\n"
                                    f"Size: {len(resp.content)} bytes\n"
                                    f"Content-Type: {content_type or 'unknown'}\n"
                                    f"Location: {location or 'n/a'}"
                                ),
                                category=f"dir-bruteforce-{path_kind}",
                                metadata={
                                    "path_classification": path_kind,
                                    "status_code": resp.status_code,
                                    "content_type": content_type,
                                    "location": location,
                                    "refinement_reason": refinement,
                                },
                            ))
                    except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                        logger.debug(f"Suppressed error: {exc}")
                    await self.wait_request_delay()

        except Exception as e:
            logger.warning(f"Dir bruteforce failed: {e}")

        return findings
