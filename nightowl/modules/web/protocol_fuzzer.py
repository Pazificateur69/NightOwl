"""Mutation-based HTTP protocol fuzzer."""

import asyncio
import logging
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Error signatures that indicate a crash or server-side failure
ERROR_SIGNATURES = [
    "internal server error",
    "traceback",
    "exception",
    "stack trace",
    "fatal error",
    "segmentation fault",
    "core dumped",
    "unhandled exception",
    "panic:",
    "runtime error",
    "syntax error",
    "mysql_",
    "pg_query",
    "ORA-",
    "SQLSTATE",
    "Microsoft OLE DB",
    "System.NullReferenceException",
    "java.lang.",
]


def _build_mutation_payloads() -> list[dict[str, str]]:
    """Create a set of mutation-based fuzz payloads."""
    return [
        {"name": "oversized_value", "value": "A" * 10000},
        {"name": "oversized_value_large", "value": "B" * 50000},
        {"name": "format_string", "value": "%s%s%s%s%s%s%s%s%s%n"},
        {"name": "format_string_alt", "value": "%x" * 50},
        {"name": "null_bytes", "value": "\x00" * 100},
        {"name": "null_byte_inject", "value": "test\x00admin"},
        {"name": "unicode_overflow", "value": "\uffff" * 5000},
        {"name": "unicode_bom", "value": "\ufeff" * 1000},
        {"name": "unicode_rtl", "value": "\u202e" * 500 + "admin"},
        {"name": "negative_number", "value": "-1"},
        {"name": "negative_large", "value": "-2147483648"},
        {"name": "negative_overflow", "value": "-99999999999999999999"},
        {"name": "large_number", "value": "99999999999999999999999999"},
        {"name": "max_int32", "value": "2147483647"},
        {"name": "max_int64", "value": "9223372036854775807"},
        {"name": "empty_value", "value": ""},
        {"name": "whitespace_only", "value": "   "},
        {"name": "special_chars", "value": "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
        {"name": "backslashes", "value": "\\" * 500},
        {"name": "crlf_injection", "value": "test\r\n\r\nInjected: true"},
        {"name": "json_inject", "value": '{"__proto__":{"admin":true}}'},
        {"name": "xml_bomb", "value": "<!DOCTYPE a[<!ENTITY x \"x\">]><a>&x;&x;&x;</a>"},
        {"name": "array_overflow", "value": "[]" * 5000},
        {"name": "deep_nesting", "value": "{" * 500 + "}" * 500},
    ]


class ProtocolFuzzerPlugin(ScannerPlugin):
    name = "protocol-fuzzer"
    description = "Mutation-based HTTP protocol fuzzer for crash detection"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # If no query params, fuzz common param names
        if not params:
            params = {"id": ["1"], "q": ["test"], "page": ["1"]}

        payloads = _build_mutation_payloads()
        timeout_val = float(self.config.get("timeout", 10))

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=timeout_val,
            ) as client:
                # Get baseline
                try:
                    t0 = time.monotonic()
                    baseline = await client.get(url)
                    baseline_time = time.monotonic() - t0
                    baseline_status = baseline.status_code
                    baseline_length = len(baseline.content)
                except Exception as e:
                    logger.warning(f"Protocol fuzzer: cannot reach baseline {url}: {e}")
                    return findings

                for param_name in list(params.keys()):
                    for payload in payloads:
                        fuzz_params = dict(params)
                        fuzz_params[param_name] = [payload["value"]]
                        flat = {k: v[0] if isinstance(v, list) else v for k, v in fuzz_params.items()}

                        fuzz_url = urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            urlencode(flat),
                            parsed.fragment,
                        ))

                        crash_indicators: list[str] = []
                        severity = Severity.MEDIUM

                        try:
                            t0 = time.monotonic()
                            resp = await client.get(fuzz_url)
                            elapsed = time.monotonic() - t0

                            # Check for server error
                            if resp.status_code >= 500:
                                crash_indicators.append(
                                    f"Server error: HTTP {resp.status_code}"
                                )
                                severity = Severity.HIGH

                            # Check for error messages in body
                            body_lower = resp.text[:5000].lower()
                            for sig in ERROR_SIGNATURES:
                                if sig.lower() in body_lower:
                                    crash_indicators.append(
                                        f"Error signature: '{sig}'"
                                    )
                                    severity = Severity.HIGH
                                    break

                            # Check for significant timing anomaly (5x baseline)
                            if baseline_time > 0 and elapsed > baseline_time * 5 and elapsed > 3:
                                crash_indicators.append(
                                    f"Timing anomaly: {elapsed:.2f}s vs baseline {baseline_time:.2f}s"
                                )

                            # Check for drastic size change (error page swap)
                            if baseline_length > 0:
                                size_ratio = len(resp.content) / baseline_length
                                if size_ratio > 5 or (size_ratio < 0.1 and baseline_length > 200):
                                    crash_indicators.append(
                                        f"Size anomaly: {len(resp.content)} bytes vs baseline {baseline_length}"
                                    )

                        except httpx.ConnectError:
                            crash_indicators.append("Connection reset by server")
                            severity = Severity.HIGH
                        except httpx.ReadTimeout:
                            crash_indicators.append(
                                f"Request timed out ({timeout_val}s)"
                            )
                            severity = Severity.MEDIUM
                        except httpx.RemoteProtocolError as e:
                            crash_indicators.append(f"Protocol error: {e}")
                            severity = Severity.HIGH
                        except Exception as e:
                            crash_indicators.append(f"Unexpected error: {type(e).__name__}: {e}")

                        if crash_indicators:
                            findings.append(Finding(
                                title=f"Fuzz crash: {payload['name']} on param '{param_name}'",
                                severity=severity,
                                cvss_score=7.5 if severity == Severity.HIGH else 5.3,
                                description=(
                                    f"Mutation payload '{payload['name']}' caused abnormal "
                                    f"server behavior on parameter '{param_name}'"
                                ),
                                evidence=(
                                    f"URL: {fuzz_url[:500]}\n"
                                    f"Payload type: {payload['name']}\n"
                                    f"Parameter: {param_name}\n"
                                    f"Indicators:\n"
                                    + "\n".join(f"  - {i}" for i in crash_indicators)
                                ),
                                remediation=(
                                    "Investigate the crash. Implement proper input validation "
                                    "and length limits. Add error handling to prevent information leakage."
                                ),
                                category="protocol-fuzzer",
                                metadata={
                                    "param": param_name,
                                    "payload_type": payload["name"],
                                    "indicators": crash_indicators,
                                },
                            ))

                        await asyncio.sleep(0.05)

        except Exception as e:
            logger.warning(f"Protocol fuzzer failed: {e}")

        return findings
