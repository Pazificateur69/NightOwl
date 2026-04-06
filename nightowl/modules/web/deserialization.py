"""Insecure deserialization scanner plugin.

Detects indicators of insecure deserialization in Java, PHP, Python, and .NET
by inspecting cookies, parameters, and response patterns for serialized object
signatures and common deserialization error messages.
"""

import base64
import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# ── Java serialization signatures ──
# Java serialized objects start with AC ED 00 05 (hex) or rO0ABX (base64)
JAVA_MAGIC_HEX = b"\xac\xed\x00\x05"
JAVA_MAGIC_B64 = "rO0ABX"

# ── PHP serialization patterns ──
# O:4:"User":2:{...}  a:2:{...}  s:5:"hello"
PHP_SERIAL_REGEX = re.compile(
    r'(?:O:\d+:"[^"]+"|a:\d+:\{|s:\d+:"[^"]*"|i:\d+;|b:[01];|N;)',
    re.IGNORECASE,
)

# ── Python pickle signatures ──
# Pickle protocol opcodes
PICKLE_MAGIC_BYTES = [
    b"\x80\x02",  # Protocol 2
    b"\x80\x03",  # Protocol 3
    b"\x80\x04",  # Protocol 4
    b"\x80\x05",  # Protocol 5
]
PICKLE_B64_PREFIXES = ["gASV", "gAJV", "gANV", "gARV", "gAVV"]

# ── .NET ViewState ──
VIEWSTATE_REGEX = re.compile(
    r'<input[^>]*name="__VIEWSTATE"[^>]*value="([^"]*)"', re.IGNORECASE
)
VIEWSTATE_GENERATOR_REGEX = re.compile(
    r'<input[^>]*name="__VIEWSTATEGENERATOR"[^>]*value="([^"]*)"', re.IGNORECASE
)
VIEWSTATE_MAC_REGEX = re.compile(
    r'<input[^>]*name="__EVENTVALIDATION"[^>]*value="([^"]*)"', re.IGNORECASE
)

# ── Deserialization error messages ──
DESER_ERROR_PATTERNS: list[tuple[str, str]] = [
    # Java
    ("java.io.objectinputstream", "Java deserialization"),
    ("java.io.invalidclassexception", "Java deserialization"),
    ("java.lang.classnotfoundexception", "Java deserialization"),
    ("java.io.streamcorruptedexception", "Java deserialization"),
    ("objectinputstream.readobject", "Java deserialization"),
    ("com.sun.org.apache.xalan", "Java deserialization"),
    ("org.apache.commons.collections", "Java deserialization (Commons Collections)"),
    # PHP
    ("unserialize()", "PHP deserialization"),
    ("__wakeup()", "PHP deserialization"),
    ("__destruct()", "PHP deserialization"),
    ("allowed_classes", "PHP deserialization"),
    # Python
    ("unpickle", "Python pickle deserialization"),
    ("pickle.loads", "Python pickle deserialization"),
    ("_pickle.unpicklingerror", "Python pickle deserialization"),
    ("cPickle", "Python pickle deserialization"),
    # .NET
    ("binaryformatter", "NET BinaryFormatter deserialization"),
    ("system.runtime.serialization", ".NET deserialization"),
    ("typenamehanding", ".NET JSON deserialization"),
    ("objectdataprovider", ".NET deserialization"),
    # Ruby
    ("marshal.load", "Ruby Marshal deserialization"),
    ("psych::disallowedclass", "Ruby YAML deserialization"),
    # Node.js
    ("node-serialize", "Node.js deserialization"),
]


class DeserializationPlugin(ScannerPlugin):
    name = "deserialization-scanner"
    description = "Detect insecure deserialization vulnerabilities"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=10
            ) as client:
                try:
                    resp = await client.get(url)
                except Exception as e:
                    logger.warning(f"Deserialization scan initial request failed: {e}")
                    return findings

                # ── Phase 1: Check cookies for serialized objects ──
                cookie_findings = self._check_cookies(resp)
                findings.extend(cookie_findings)

                # ── Phase 2: Check URL parameters ──
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                param_findings = self._check_params(params)
                findings.extend(param_findings)

                # ── Phase 3: Check response body for .NET ViewState ──
                viewstate_findings = self._check_viewstate(resp.text, url)
                findings.extend(viewstate_findings)

                # ── Phase 4: Check for deserialization errors in responses ──
                error_findings = self._check_error_messages(resp.text, url)
                findings.extend(error_findings)

                # ── Phase 5: Active probing with malformed serialized data ──
                active_findings = await self._active_probe(client, url, resp)
                findings.extend(active_findings)

        except Exception as e:
            logger.warning(f"Deserialization scan failed: {e}")

        return findings

    def _check_cookies(self, resp: httpx.Response) -> list[Finding]:
        """Inspect cookies for serialized object signatures."""
        findings: list[Finding] = []

        for cookie in resp.cookies.jar:
            value = cookie.value

            # Check for Java serialized object (base64)
            if JAVA_MAGIC_B64 in value:
                findings.append(self._make_finding(
                    "Java Serialized Object in Cookie",
                    Severity.HIGH, 8.1,
                    f"Cookie '{cookie.name}' contains a Java serialized object (base64 prefix rO0ABX). "
                    "If this is deserialized server-side, it may be exploitable via gadget chains.",
                    f"Cookie: {cookie.name}\nValue (truncated): {value[:100]}...\nSignature: Java rO0ABX prefix",
                    "java",
                ))

            # Check for base64-encoded Java
            try:
                decoded = base64.b64decode(value, validate=True)
                if decoded.startswith(JAVA_MAGIC_HEX):
                    findings.append(self._make_finding(
                        "Java Serialized Object in Cookie (raw)",
                        Severity.HIGH, 8.1,
                        f"Cookie '{cookie.name}' contains a base64-encoded Java serialized object.",
                        f"Cookie: {cookie.name}\nDecoded magic bytes: AC ED 00 05",
                        "java",
                    ))
            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                logger.debug(f"Suppressed error: {exc}")

            # Check for PHP serialized data
            if PHP_SERIAL_REGEX.search(value):
                findings.append(self._make_finding(
                    "PHP Serialized Data in Cookie",
                    Severity.HIGH, 7.5,
                    f"Cookie '{cookie.name}' contains PHP serialized data. "
                    "PHP object injection via unserialize() can lead to RCE.",
                    f"Cookie: {cookie.name}\nValue (truncated): {value[:100]}...\nPattern: PHP serialization",
                    "php",
                ))

            # Check for Python pickle (base64)
            for prefix in PICKLE_B64_PREFIXES:
                if value.startswith(prefix):
                    findings.append(self._make_finding(
                        "Python Pickle Object in Cookie",
                        Severity.CRITICAL, 9.8,
                        f"Cookie '{cookie.name}' appears to contain a Python pickle object. "
                        "Pickle deserialization of untrusted data leads directly to RCE.",
                        f"Cookie: {cookie.name}\nValue (truncated): {value[:100]}...\nSignature: Pickle base64 prefix",
                        "python",
                    ))
                    break

        return findings

    def _check_params(self, params: dict) -> list[Finding]:
        """Check URL parameters for serialized object indicators."""
        findings: list[Finding] = []

        for name, values in params.items():
            value = values[0] if isinstance(values, list) else values

            if JAVA_MAGIC_B64 in value:
                findings.append(self._make_finding(
                    f"Java Serialized Object in Parameter '{name}'",
                    Severity.HIGH, 8.1,
                    f"URL parameter '{name}' contains a Java serialized object.",
                    f"Parameter: {name}\nValue (truncated): {value[:100]}...",
                    "java",
                ))

            if PHP_SERIAL_REGEX.search(value):
                findings.append(self._make_finding(
                    f"PHP Serialized Data in Parameter '{name}'",
                    Severity.HIGH, 7.5,
                    f"URL parameter '{name}' contains PHP serialized data.",
                    f"Parameter: {name}\nValue (truncated): {value[:100]}...",
                    "php",
                ))

            for prefix in PICKLE_B64_PREFIXES:
                if value.startswith(prefix):
                    findings.append(self._make_finding(
                        f"Python Pickle Object in Parameter '{name}'",
                        Severity.CRITICAL, 9.8,
                        f"URL parameter '{name}' contains a Python pickle object.",
                        f"Parameter: {name}\nValue (truncated): {value[:100]}...",
                        "python",
                    ))
                    break

        return findings

    def _check_viewstate(self, body: str, url: str) -> list[Finding]:
        """Check for .NET ViewState without MAC validation."""
        findings: list[Finding] = []

        vs_match = VIEWSTATE_REGEX.search(body)
        if not vs_match:
            return findings

        viewstate_value = vs_match.group(1)
        has_event_validation = bool(VIEWSTATE_MAC_REGEX.search(body))
        has_generator = bool(VIEWSTATE_GENERATOR_REGEX.search(body))

        # Try to decode ViewState to check for MAC
        try:
            decoded = base64.b64decode(viewstate_value)
            # ViewState without MAC is typically shorter and doesn't end with 20-byte HMAC
            # A properly MAC'd ViewState has an HMAC signature appended
            has_mac = len(decoded) > 20 and len(viewstate_value) > 50
        except (OSError, RuntimeError, ValueError, Exception) as exc:
            logger.debug(f"Error: {exc}")
            has_mac = True  # assume protected if we can't decode

        if not has_event_validation:
            severity = Severity.HIGH if not has_mac else Severity.MEDIUM
            cvss = 7.5 if not has_mac else 5.3
            findings.append(
                Finding(
                    title=".NET ViewState Without Event Validation",
                    severity=severity,
                    cvss_score=cvss,
                    description=(
                        "The application uses .NET ViewState without EventValidation. "
                        "This may allow ViewState deserialization attacks if MAC validation "
                        "is also disabled."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"ViewState present: Yes\n"
                        f"EventValidation: No\n"
                        f"ViewStateGenerator: {'Yes' if has_generator else 'No'}\n"
                        f"ViewState (truncated): {viewstate_value[:80]}..."
                    ),
                    remediation=(
                        "Enable ViewState MAC validation (enableViewStateMac=true). "
                        "Enable EventValidation. Use ViewState encryption. "
                        "Consider migrating to ASP.NET Core which doesn't use ViewState."
                    ),
                    category="deserialization",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Unsafe_use_of_Reflection",
                        "https://blog.liquidsec.net/2021/06/01/asp-net-viewstate-deserialization/",
                    ],
                )
            )

        return findings

    def _check_error_messages(self, body: str, url: str) -> list[Finding]:
        """Check response body for deserialization error messages."""
        findings: list[Finding] = []
        body_lower = body.lower()
        found_errors: list[tuple[str, str]] = []

        for pattern, tech in DESER_ERROR_PATTERNS:
            if pattern in body_lower:
                found_errors.append((pattern, tech))

        if found_errors:
            technologies = list({tech for _, tech in found_errors})
            findings.append(
                Finding(
                    title=f"Deserialization Error Messages Exposed ({', '.join(technologies)})",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    description=(
                        "Response contains deserialization-related error messages, "
                        "indicating the application processes serialized data. "
                        "This information helps attackers craft exploitation payloads."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Technologies: {', '.join(technologies)}\n"
                        f"Patterns found:\n"
                        + "\n".join(f"  - {p} ({t})" for p, t in found_errors[:8])
                    ),
                    remediation=(
                        "Suppress detailed error messages in production. "
                        "Avoid deserializing untrusted data. Use allowlists for deserialized classes."
                    ),
                    category="deserialization",
                )
            )

        return findings

    async def _active_probe(
        self, client: httpx.AsyncClient, url: str, original_resp: httpx.Response
    ) -> list[Finding]:
        """Actively probe with malformed serialized payloads to trigger errors."""
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Malformed serialized data payloads
        probes: list[tuple[str, str, str]] = [
            # Malformed Java serialized object (will trigger error if deserialized)
            ("rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtR/", "Java", "java serialized probe"),
            # Malformed PHP serialized data
            ('O:4:"Test":1:{s:4:"test";s:4:"test";}', "PHP", "php serialized probe"),
            # YAML deserialization probe
            ("!!python/object/apply:os.system ['id']", "Python YAML", "yaml probe"),
        ]

        # Test cookies by replaying with modified values
        for cookie in original_resp.cookies.jar:
            for payload, tech, desc in probes:
                try:
                    cookies = {cookie.name: payload}
                    resp = await client.get(url, cookies=cookies)
                    body_lower = resp.text.lower()

                    for pattern, error_tech in DESER_ERROR_PATTERNS:
                        if pattern in body_lower:
                            findings.append(self._make_finding(
                                f"Deserialization Processing Confirmed via Cookie '{cookie.name}'",
                                Severity.HIGH, 8.1,
                                f"Injecting a malformed {tech} payload into cookie '{cookie.name}' "
                                f"triggered a deserialization error ({error_tech}). "
                                "This confirms the server deserializes cookie data.",
                                f"Cookie: {cookie.name}\nPayload: {payload[:80]}\nError: {pattern}",
                                tech.lower().replace(" ", "_"),
                            ))
                            break
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

        # Test URL parameters
        for param_name in list(params.keys())[:5]:
            for payload, tech, desc in probes:
                try:
                    test_params = {
                        k: v[0] if isinstance(v, list) else v
                        for k, v in params.items()
                    }
                    test_params[param_name] = payload
                    test_url = urlunparse(
                        parsed._replace(query=urlencode(test_params))
                    )
                    resp = await client.get(test_url)
                    body_lower = resp.text.lower()

                    for pattern, error_tech in DESER_ERROR_PATTERNS:
                        if pattern in body_lower:
                            findings.append(self._make_finding(
                                f"Deserialization Processing Confirmed via Parameter '{param_name}'",
                                Severity.HIGH, 8.1,
                                f"Injecting a malformed {tech} payload into parameter '{param_name}' "
                                f"triggered a deserialization error ({error_tech}).",
                                f"Parameter: {param_name}\nPayload: {payload[:80]}\nError: {pattern}",
                                tech.lower().replace(" ", "_"),
                            ))
                            break
                except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                    logger.debug(f"Suppressed error: {exc}")
                    continue

        return findings

    def _make_finding(
        self, title: str, severity: Severity, cvss: float,
        description: str, evidence: str, tech: str,
    ) -> Finding:
        """Create a standard deserialization finding."""
        return Finding(
            title=title,
            severity=severity,
            cvss_score=cvss,
            description=description,
            evidence=evidence,
            remediation=(
                "Avoid deserializing untrusted data. If deserialization is required, "
                "use allowlists for permitted classes. Implement integrity checks (HMAC). "
                "Monitor for deserialization-related errors."
            ),
            category="deserialization",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
                "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            ],
            metadata={"technology": tech},
        )
