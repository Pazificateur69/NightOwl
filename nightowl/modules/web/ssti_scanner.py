"""Server-Side Template Injection (SSTI) scanner plugin.

Detects SSTI vulnerabilities by injecting template expressions into URL
parameters and POST body fields, then checking if the server evaluates them.
Tests for multiple template engines (Jinja2, Twig, Freemarker, Velocity, etc.).
"""

import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target

logger = logging.getLogger("nightowl")

# Payload tuples: (payload, expected_output, engine_hint)
# Using math expressions whose output is unique and unlikely to appear naturally
SSTI_PAYLOADS: list[tuple[str, str, str]] = [
    # Universal math-based detection
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Groovy/EL"),
    ("#{7*7}", "49", "Ruby ERB/Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/EJS/JSP"),
    ("{7*7}", "49", "Smarty"),
    ("{{7*'7'}}", "7777777", "Jinja2"),  # Jinja2-specific: string repeat
    ("${7*7}", "49", "Spring EL"),

    # Unique marker strings (less likely to false-positive)
    ("{{71*73}}", "5183", "Jinja2/Twig"),
    ("${71*73}", "5183", "Freemarker/Groovy"),
    ("#{71*73}", "5183", "Ruby ERB/Thymeleaf"),
    ("<%= 71*73 %>", "5183", "ERB/EJS"),

    # Engine-specific identification payloads
    ("{{config}}", "<Config", "Jinja2 (Flask)"),
    ("{{config.items()}}", "SECRET_KEY", "Jinja2 (Flask config leak)"),
    ("{{self.__class__}}", "TemplateReference", "Jinja2"),
    ("{{request.application.__globals__}}", "os", "Jinja2 (Flask RCE path)"),
    ("${T(java.lang.Runtime)}", "java.lang.Runtime", "Spring EL (Java)"),
    ("{{range.constructor('return 1')()}}", "1", "AngularJS sandbox escape"),
    ("#{T(java.lang.Runtime).getRuntime()}", "Runtime", "Thymeleaf/Spring"),
]

# Second-stage payloads to confirm and identify exact engine
CONFIRM_PAYLOADS: dict[str, list[tuple[str, str]]] = {
    "Jinja2": [
        ("{{namespace.__init__.__globals__}}", "__builtins__"),
        ("{{lipsum.__globals__}}", "os"),
    ],
    "Twig": [
        ("{{_self.env.display('nightowl')}}", "nightowl"),
        ("{{dump(app)}}", "AppVariable"),
    ],
    "Freemarker": [
        ('<#assign ex="freemarker.template.utility.Execute"?new()>', ""),
        ("${.version}", "2."),
    ],
    "Velocity": [
        ("#set($x=71*73)$x", "5183"),
    ],
}

# Common parameter names that might accept template-like input
TEMPLATE_PARAM_NAMES = {
    "template",
    "name",
    "message",
    "msg",
    "text",
    "content",
    "body",
    "title",
    "page",
    "view",
    "render",
    "email",
    "subject",
    "comment",
    "desc",
    "description",
    "greeting",
    "preview",
    "format",
    "lang",
    "locale",
}


class SSTIPlugin(ScannerPlugin):
    name = "ssti-scanner"
    description = "Detect Server-Side Template Injection vulnerabilities"
    version = "1.0.0"
    stage = "scan"

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no URL params, generate test parameters
        if not params:
            params = {k: ["test"] for k in list(TEMPLATE_PARAM_NAMES)[:6]}

        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=10
            ) as client:
                # Track which params are already confirmed vulnerable
                confirmed_params: set[str] = set()

                for param_name in params:
                    if param_name in confirmed_params:
                        continue

                    # ── GET-based SSTI testing ──
                    for payload, expected, engine in SSTI_PAYLOADS:
                        if param_name in confirmed_params:
                            break

                        test_params = {
                            k: v[0] if isinstance(v, list) else v
                            for k, v in params.items()
                        }
                        test_params[param_name] = payload
                        test_url = urlunparse(
                            parsed._replace(query=urlencode(test_params))
                        )

                        try:
                            resp = await client.get(test_url)
                            finding = self._check_response(
                                resp.text, payload, expected, engine,
                                param_name, test_url, "GET"
                            )
                            if finding:
                                findings.append(finding)
                                confirmed_params.add(param_name)
                                break
                        except Exception:
                            continue

                    # ── POST-based SSTI testing ──
                    if param_name in confirmed_params:
                        continue

                    for payload, expected, engine in SSTI_PAYLOADS[:8]:
                        if param_name in confirmed_params:
                            break

                        post_data = {param_name: payload}
                        try:
                            resp = await client.post(url, data=post_data)
                            finding = self._check_response(
                                resp.text, payload, expected, engine,
                                param_name, url, "POST"
                            )
                            if finding:
                                findings.append(finding)
                                confirmed_params.add(param_name)
                                break
                        except Exception:
                            continue

                        # Also try JSON body
                        try:
                            resp = await client.post(
                                url,
                                json=post_data,
                                headers={"Content-Type": "application/json"},
                            )
                            finding = self._check_response(
                                resp.text, payload, expected, engine,
                                param_name, url, "POST (JSON)"
                            )
                            if finding:
                                findings.append(finding)
                                confirmed_params.add(param_name)
                                break
                        except Exception:
                            continue

        except Exception as e:
            logger.warning(f"SSTI scan failed: {e}")

        return findings

    def _check_response(
        self,
        response_body: str,
        payload: str,
        expected: str,
        engine: str,
        param_name: str,
        url: str,
        method: str,
    ) -> Finding | None:
        """Check if the response indicates successful template injection."""
        if not expected:
            return None

        # The expected output must be present but the raw payload should ideally not be
        # (to avoid false positives from reflection without evaluation)
        if expected in response_body:
            # Make sure it's actual evaluation, not just reflection of the payload itself
            # e.g., if payload is "{{7*7}}" and response has "{{7*7}}" alongside "49",
            # the "49" might be unrelated. But if "49" appears without the raw payload, strong signal.
            raw_in_response = payload in response_body

            if raw_in_response and expected == "49":
                # "49" is common -- could be a false positive if payload is also reflected
                # Check for a less ambiguous marker
                return None

            confidence = "high" if not raw_in_response else "medium"

            return Finding(
                title=f"Server-Side Template Injection in '{param_name}' ({engine})",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description=(
                    f"SSTI detected via {method} parameter '{param_name}'. "
                    f"Template engine appears to be {engine}. "
                    "SSTI typically leads to Remote Code Execution (RCE), "
                    "allowing an attacker to execute arbitrary commands on the server."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Method: {method}\n"
                    f"Parameter: {param_name}\n"
                    f"Payload: {payload}\n"
                    f"Expected in response: {expected}\n"
                    f"Confidence: {confidence}"
                ),
                remediation=(
                    "Never pass user input directly into template rendering. "
                    "Use sandboxed template environments. "
                    "Apply strict input validation and use template engines safely "
                    "(e.g., Jinja2 SandboxedEnvironment)."
                ),
                category="ssti",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
                    "https://portswigger.net/research/server-side-template-injection",
                ],
                metadata={
                    "engine": engine,
                    "confidence": confidence,
                    "method": method,
                    "parameter": param_name,
                },
            )

        return None
