"""Server-Side Template Injection (SSTI) scanner plugin."""

import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, Severity
from nightowl.models.target import Target
from nightowl.utils.web_discovery import discover_web_attack_surface, form_to_legacy_dict

logger = logging.getLogger("nightowl")

SSTI_PAYLOADS: list[tuple[str, str, str]] = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Groovy/EL"),
    ("#{7*7}", "49", "Ruby ERB/Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/EJS/JSP"),
    ("{7*7}", "49", "Smarty"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${7*7}", "49", "Spring EL"),
    ("{{71*73}}", "5183", "Jinja2/Twig"),
    ("${71*73}", "5183", "Freemarker/Groovy"),
    ("#{71*73}", "5183", "Ruby ERB/Thymeleaf"),
    ("<%= 71*73 %>", "5183", "ERB/EJS"),
    ("{{config}}", "<Config", "Jinja2 (Flask)"),
    ("{{config.items()}}", "SECRET_KEY", "Jinja2 (Flask config leak)"),
    ("{{self.__class__}}", "TemplateReference", "Jinja2"),
    ("{{request.application.__globals__}}", "os", "Jinja2 (Flask RCE path)"),
    ("${T(java.lang.Runtime)}", "java.lang.Runtime", "Spring EL (Java)"),
    ("{{range.constructor('return 1')()}}", "1", "AngularJS sandbox escape"),
    ("#{T(java.lang.Runtime).getRuntime()}", "Runtime", "Thymeleaf/Spring"),
]

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
    config_schema = {
        "discovery_depth": (int, 1),
        "discovery_max_pages": (int, 6),
        "discovery_max_urls": (int, 10),
        "discovery_max_forms": (int, 10),
    }

    @staticmethod
    def _default_form_value(_param_name: str) -> str:
        return "test"

    def _extract_form_targets(self, html: str, base_url: str) -> list[dict]:
        form_targets: list[dict] = []
        form_pattern = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
        attr_pattern = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:]*)=(['\"])(.*?)\2", re.S)
        input_pattern = re.compile(r"<(?:input|textarea)\b([^>]*)>", re.I | re.S)

        for form_match in form_pattern.finditer(html):
            raw_attrs = {
                key.lower(): value for key, _, value in attr_pattern.findall(form_match.group(1))
            }
            method = raw_attrs.get("method", "get").lower()
            if method not in {"get", "post"}:
                continue
            action = raw_attrs.get("action", "").strip()
            action_url = action if action.startswith("http") else (
                base_url.rstrip("/") + "/" + action.lstrip("/") if action else base_url
            )
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
                        "attackable_params": attackable_params,
                    }
                )
        return form_targets

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url or f"https://{target.host}"

        try:
            async with self.create_http_client() as client:
                baseline = await client.get(url, headers=self.get_request_headers())
                discovery = await discover_web_attack_surface(
                    client,
                    str(baseline.url),
                    default_value_fn=self._default_form_value,
                    max_depth=self.config.get("discovery_depth", 1),
                    max_pages=self.config.get("discovery_max_pages", 6),
                    max_urls_with_params=self.config.get("discovery_max_urls", 10),
                    max_forms=self.config.get("discovery_max_forms", 10),
                    request_headers=self.get_request_headers(),
                    wait_hook=self.wait_request_delay,
                )

                candidate_urls = [str(baseline.url)]
                for discovered_url in discovery.urls_with_params:
                    if discovered_url not in candidate_urls:
                        candidate_urls.append(discovered_url)

                form_targets = self._extract_form_targets(baseline.text, str(baseline.url))
                seen_forms = {
                    (form["method"], form["url"], tuple(sorted(form["attackable_params"])))
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

                confirmed_params: set[str] = set()
                found_surface = False

                for candidate_url in candidate_urls:
                    parsed = urlparse(candidate_url)
                    params = parse_qs(parsed.query)
                    if not params:
                        continue
                    found_surface = True
                    for param_name in params:
                        if param_name in confirmed_params:
                            continue
                        for payload, expected, engine in SSTI_PAYLOADS:
                            if param_name in confirmed_params:
                                break
                            test_params = {
                                k: v[0] if isinstance(v, list) else v
                                for k, v in params.items()
                            }
                            test_params[param_name] = payload
                            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                            try:
                                resp = await client.get(test_url, headers=self.get_request_headers())
                                finding = self._check_response(
                                    resp.text, payload, expected, engine, param_name, test_url, "GET"
                                )
                                if finding:
                                    findings.append(finding)
                                    confirmed_params.add(param_name)
                                    break
                            except Exception as exc:
                                logger.debug(f"Suppressed error: {exc}")
                                continue
                            finally:
                                await self.wait_request_delay()

                for form_target in form_targets:
                    found_surface = True
                    for param_name in form_target["attackable_params"]:
                        if param_name in confirmed_params:
                            continue
                        for payload, expected, engine in SSTI_PAYLOADS[:8]:
                            if param_name in confirmed_params:
                                break
                            payload_params = dict(form_target["params"])
                            payload_params[param_name] = payload
                            try:
                                if form_target["method"] == "post":
                                    resp = await client.post(
                                        form_target["url"],
                                        data=payload_params,
                                        headers=self.get_request_headers(),
                                    )
                                    finding = self._check_response(
                                        resp.text, payload, expected, engine, param_name, form_target["url"], "POST"
                                    )
                                    if finding:
                                        findings.append(finding)
                                        confirmed_params.add(param_name)
                                        break

                                    resp = await client.post(
                                        form_target["url"],
                                        json=payload_params,
                                        headers=self.get_request_headers({"Content-Type": "application/json"}),
                                    )
                                    finding = self._check_response(
                                        resp.text, payload, expected, engine, param_name, form_target["url"], "POST (JSON)"
                                    )
                                else:
                                    resp = await client.get(
                                        form_target["url"],
                                        params=payload_params,
                                        headers=self.get_request_headers(),
                                    )
                                    finding = self._check_response(
                                        resp.text, payload, expected, engine, param_name, form_target["url"], "GET (FORM)"
                                    )
                                if finding:
                                    findings.append(finding)
                                    confirmed_params.add(param_name)
                                    break
                            except Exception as exc:
                                logger.debug(f"Suppressed error: {exc}")
                                continue
                            finally:
                                await self.wait_request_delay()

                if not found_surface:
                    parsed = urlparse(url)
                    params = {k: ["test"] for k in list(TEMPLATE_PARAM_NAMES)[:6]}
                    for param_name in params:
                        if param_name in confirmed_params:
                            continue
                        for payload, expected, engine in SSTI_PAYLOADS:
                            test_params = {k: v[0] for k, v in params.items()}
                            test_params[param_name] = payload
                            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                            try:
                                resp = await client.get(test_url, headers=self.get_request_headers())
                                finding = self._check_response(
                                    resp.text, payload, expected, engine, param_name, test_url, "GET"
                                )
                                if finding:
                                    findings.append(finding)
                                    confirmed_params.add(param_name)
                                    break
                            except Exception as exc:
                                logger.debug(f"Suppressed error: {exc}")
                                continue
                            finally:
                                await self.wait_request_delay()

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
        if not expected:
            return None

        if expected in response_body:
            raw_in_response = payload in response_body
            if raw_in_response and expected == "49":
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
