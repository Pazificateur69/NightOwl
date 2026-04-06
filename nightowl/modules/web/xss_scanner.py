"""Reflected XSS scanner plugin."""

import logging
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from nightowl.core.plugin_base import ScannerPlugin
from nightowl.models.finding import Finding, FindingState, Severity
from nightowl.models.target import Target
from nightowl.utils.web_discovery import discover_web_attack_surface, form_to_legacy_dict

logger = logging.getLogger("nightowl")

# Use a unique canary to distinguish real reflection from coincidental matches
_CANARY = "n1GhT0wL"
XSS_PAYLOADS = [
    f'<script>alert("{_CANARY}")</script>',
    f'"><img src=x onerror=alert("{_CANARY}")>',
    f"<svg/onload=alert('{_CANARY}')>",
    f'"><svg onload=alert("{_CANARY}")>',
]


def _payload_variants(payload: str) -> list[str]:
    variants = [payload]
    json_escaped = payload.replace("\\", "\\\\").replace('"', '\\"').replace("</", "<\\/")
    if json_escaped not in variants:
        variants.append(json_escaped)
    json_double_escaped = json_escaped.replace("\\", "\\\\")
    if json_double_escaped not in variants:
        variants.append(json_double_escaped)
    return variants


def _canonicalize_reflection_body(body: str) -> str:
    """Normalize repeated JSON-style escaping for reflection matching."""
    canonical = body
    for _ in range(4):
        updated = re.sub(r"\\+([\"/])", r"\1", canonical)
        if updated == canonical:
            break
        canonical = updated
    return canonical


def _find_reflected_payload(payload: str, body: str) -> str | None:
    for candidate in _payload_variants(payload):
        if candidate in body:
            return candidate
    canonical_body = _canonicalize_reflection_body(body)
    for candidate in _payload_variants(payload):
        if candidate in canonical_body:
            return candidate
    return None


def _json_output_renders_html(reflected_payload: str, body: str) -> bool:
    stripped = body.strip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False

    lowered = body.lower()
    if '"output"' not in lowered:
        return False

    canonical_body = _canonicalize_reflection_body(body)
    if reflected_payload not in body and reflected_payload not in canonical_body:
        return False

    # WebGoat-style challenge responses often return HTML fragments inside an
    # "output" JSON field that the frontend later injects into the DOM.
    return any(token in lowered for token in ("<br", "<\\/script>", "<hr", "<p>", "<div"))


def _is_dangerous_context(payload: str, body: str) -> bool:
    """Check if the reflected payload appears in an executable context.

    Returns True only when the payload lands in a position where a browser
    would actually execute it (inside HTML body, unquoted attribute, or
    inline script). Returns False if the reflection is inside a JSON blob,
    a JavaScript string literal, an HTML comment, or is clearly entity-encoded.
    """
    idx = body.find(payload)
    if idx < 0:
        return False

    # Grab context around the reflection
    ctx_start = max(0, idx - 200)
    ctx_end = min(len(body), idx + len(payload) + 200)
    context = body[ctx_start:ctx_end]

    # If the payload is entity-encoded (< appears as &lt;), not exploitable
    encoded_check = body[max(0, idx - 5):idx + len(payload) + 5]
    if "&lt;" in encoded_check or "&gt;" in encoded_check:
        return False

    # If reflection is inside a JSON response body, usually not exploitable
    stripped = body.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return False

    # If reflection is inside an HTML comment, not exploitable
    comment_before = body.rfind("<!--", ctx_start, idx)
    comment_after = body.find("-->", idx)
    if comment_before >= 0 and (comment_after < 0 or comment_after > idx):
        return False

    # If inside a <script> block as a JS string, check for quote breaks
    script_start = body.rfind("<script", ctx_start, idx)
    script_end = body.find("</script>", idx)
    if script_start >= 0 and script_end > idx:
        # Payload is inside a script block — only dangerous if it breaks out
        # of a string context (has unescaped quotes)
        inner = body[script_start:idx]
        # Count unescaped quotes to see if we're in a string
        single_quotes = len(re.findall(r"(?<!\\)'", inner))
        double_quotes = len(re.findall(r'(?<!\\)"', inner))
        # If inside a string (odd number of quotes), payload must break out
        if single_quotes % 2 == 1 or double_quotes % 2 == 1:
            # Check if payload actually contains a matching quote break
            if "'" not in payload and '"' not in payload:
                return False

    # The payload's HTML tags appear unescaped — dangerous context
    return True


def _response_looks_like_html(content_type: str, body: str) -> bool:
    """Allow HTML-like responses even when content-type headers are weak."""
    lowered = content_type.lower()
    if "html" in lowered or "xhtml" in lowered:
        return True

    body_start = body.lstrip()[:200].lower()
    return "<html" in body_start or "<!doctype html" in body_start


def _confidence_for_payload(payload: str, response_text: str, param_name: str) -> tuple[FindingState, float]:
    """Estimate confidence from the reflected sink shape."""
    lowered = response_text.lower()
    if "<script" in payload and "<script" in lowered:
        return FindingState.CONFIRMED, 0.96
    if "onerror=" in payload or "onload=" in payload:
        return FindingState.CONFIRMED, 0.93
    if param_name.lower() in {"q", "query", "search"}:
        return FindingState.SUSPECTED, 0.82
    return FindingState.SUSPECTED, 0.87


class XSSScannerPlugin(ScannerPlugin):
    name = "xss-scanner"
    description = "Test for reflected Cross-Site Scripting (XSS)"
    version = "1.0.0"
    stage = "scan"

    config_schema = {
        "discovery_depth": (int, 1),
        "discovery_max_pages": (int, 6),
        "discovery_max_urls": (int, 10),
        "discovery_max_forms": (int, 10),
    }

    _is_dangerous_context = staticmethod(_is_dangerous_context)
    _response_looks_like_html = staticmethod(_response_looks_like_html)
    _confidence_for_payload = staticmethod(_confidence_for_payload)
    _find_reflected_payload = staticmethod(_find_reflected_payload)
    _json_output_renders_html = staticmethod(_json_output_renders_html)

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        """Extract forms and their input fields from HTML for POST-based XSS testing."""
        forms: list[dict] = []
        form_pattern = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
        attr_pattern = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:]*)=(['\"])(.*?)\2", re.S)
        input_pattern = re.compile(r"<(?:input|textarea)\b([^>]*)>", re.I | re.S)

        for form_match in form_pattern.finditer(html):
            raw_attrs = {
                key.lower(): value for key, _, value in attr_pattern.findall(form_match.group(1))
            }
            method = raw_attrs.get("method", "get").lower()
            action = raw_attrs.get("action", "").strip()
            action_url = urljoin(base_url, action) if action else base_url

            params: dict[str, str] = {}
            text_params: list[str] = []
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
                params[name] = attrs.get("value", "") or "test"
                if input_type not in {"hidden", "checkbox", "radio"}:
                    text_params.append(name)

            if text_params:
                forms.append({
                    "method": method,
                    "url": action_url,
                    "params": params,
                    "text_params": text_params,
                })
        return forms

    @staticmethod
    def _default_form_value(param_name: str) -> str:
        lowered = param_name.lower()
        if lowered in {"q", "query", "search", "name", "username", "comment", "message"}:
            return "test"
        if lowered in {"id", "item", "page"}:
            return "1"
        return "test"

    def _check_xss_in_response(
        self, payload: str, resp_text: str, param_name: str
    ) -> Finding | None:
        """Check if a payload is reflected in a dangerous context. Returns a Finding or None."""
        reflected_payload = self._find_reflected_payload(payload, resp_text)
        if not reflected_payload:
            return None

        content_type = ""
        html_like = self._response_looks_like_html(content_type, resp_text)
        json_rendered_output = self._json_output_renders_html(reflected_payload, resp_text)

        if not html_like and not json_rendered_output:
            return None

        if html_like and not _is_dangerous_context(reflected_payload, resp_text):
            return None

        finding_state, confidence_score = self._confidence_for_payload(
            payload, resp_text, param_name
        )
        if json_rendered_output:
            finding_state = FindingState.SUSPECTED
            confidence_score = min(confidence_score, 0.78)

        return Finding(
            title=f"Reflected XSS in parameter '{param_name}'",
            severity=Severity.HIGH,
            finding_state=finding_state,
            confidence_score=confidence_score,
            cvss_score=6.1,
            description=(
                f"The parameter '{param_name}' reflects user input without encoding, allowing script injection."
            ),
            evidence=(
                f"Payload: {payload}\n"
                + (
                    "Payload reflected inside a JSON output field that appears to carry rendered HTML."
                    if json_rendered_output
                    else "Payload reflected unescaped in executable HTML context."
                )
            ),
            remediation="Implement output encoding (HTML entity escaping) on all user-controlled values. Deploy a strict Content-Security-Policy.",
            category="xss",
            references=["https://owasp.org/www-community/attacks/xss/"],
        )

    async def run(self, target: Target, **kwargs) -> list[Finding]:
        findings = []
        url = target.url or f"https://{target.host}"
        tested_params: set[str] = set()

        try:
            async with self.create_http_client() as client:
                await self.bootstrap_auth(client)
                # Get baseline response
                baseline = await client.get(url, headers=self.get_request_headers())
                baseline_has_canary = _CANARY in baseline.text
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
                candidate_forms = self._extract_forms(baseline.text, str(baseline.url))
                seen_forms = {
                    (
                        form["method"],
                        form["url"],
                        tuple(sorted(form["text_params"])),
                    )
                    for form in candidate_forms
                }
                for discovered_form in discovery.forms:
                    legacy_form = form_to_legacy_dict(discovered_form, param_key="text_params")
                    form_key = (
                        legacy_form["method"],
                        legacy_form["url"],
                        tuple(sorted(legacy_form["text_params"])),
                    )
                    if form_key in seen_forms:
                        continue
                    seen_forms.add(form_key)
                    candidate_forms.append(legacy_form)

                # Phase 1: Test GET query parameters
                for candidate_url in candidate_urls:
                    parsed = urlparse(candidate_url)
                    params = parse_qs(parsed.query)
                    if not params:
                        continue
                    for param_name in params:
                        if param_name in tested_params:
                            continue
                        for payload in XSS_PAYLOADS:
                            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                            test_params[param_name] = payload
                            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                            try:
                                resp = await client.get(test_url, headers=self.get_request_headers())

                                reflected_payload = self._find_reflected_payload(payload, resp.text)
                                if not reflected_payload or baseline_has_canary:
                                    continue

                                content_type = resp.headers.get("content-type", "")
                                html_like = self._response_looks_like_html(content_type, resp.text)
                                json_rendered_output = self._json_output_renders_html(
                                    reflected_payload, resp.text
                                )
                                if not html_like and not json_rendered_output:
                                    continue

                                if html_like and not _is_dangerous_context(reflected_payload, resp.text):
                                    logger.debug(
                                        f"[{self.name}] Payload reflected in {param_name} "
                                        f"but in non-executable context — skipping"
                                    )
                                    continue

                                finding_state, confidence_score = self._confidence_for_payload(
                                    payload,
                                    resp.text,
                                    param_name,
                                )
                                if json_rendered_output:
                                    finding_state = FindingState.SUSPECTED
                                    confidence_score = min(confidence_score, 0.78)

                                findings.append(Finding(
                                    title=f"Reflected XSS in parameter '{param_name}'",
                                    severity=Severity.HIGH,
                                    finding_state=finding_state,
                                    confidence_score=confidence_score,
                                    cvss_score=6.1,
                                    description=(
                                        f"The parameter '{param_name}' reflects user input without encoding, allowing script injection."
                                    ),
                                    evidence=(
                                        f"URL: {test_url}\nPayload: {payload}\n"
                                        + (
                                            "Payload reflected inside a JSON output field that appears to carry rendered HTML."
                                            if json_rendered_output
                                            else "Payload reflected unescaped in executable HTML context."
                                        )
                                    ),
                                    remediation="Implement output encoding (HTML entity escaping) on all user-controlled values. Deploy a strict Content-Security-Policy.",
                                    category="xss",
                                    references=["https://owasp.org/www-community/attacks/xss/"],
                                    metadata={"method": "GET", "param": param_name},
                                ))
                                tested_params.add(param_name)
                                break  # one finding per param
                            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                                logger.debug(f"Suppressed error: {exc}")
                                continue
                            finally:
                                await self.wait_request_delay()

                # Phase 2: Test POST form parameters
                for form in candidate_forms:
                    for param_name in form["text_params"]:
                        if param_name in tested_params:
                            continue
                        for payload in XSS_PAYLOADS:
                            form_data = dict(form["params"])
                            form_data[param_name] = payload
                            try:
                                if form["method"] == "post":
                                    resp = await client.post(
                                        form["url"],
                                        data=form_data,
                                        headers=self.get_request_headers(),
                                    )
                                else:
                                    resp = await client.get(
                                        form["url"],
                                        params=form_data,
                                        headers=self.get_request_headers(),
                                    )

                                if _CANARY in baseline.text:
                                    continue

                                finding = self._check_xss_in_response(payload, resp.text, param_name)
                                if finding:
                                    finding.evidence = (
                                        f"Form action: {form['url']}\n"
                                        f"Method: {form['method'].upper()}\n"
                                        + finding.evidence
                                    )
                                    finding.metadata = {
                                        "method": form["method"].upper(),
                                        "param": param_name,
                                        "action_url": form["url"],
                                    }
                                    findings.append(finding)
                                    tested_params.add(param_name)
                                    break
                            except (OSError, RuntimeError, ValueError, httpx.RequestError) as exc:
                                logger.debug(f"Suppressed error: {exc}")
                                continue
                            finally:
                                await self.wait_request_delay()

        except Exception as e:
            logger.warning(f"[{self.name}] Error: {e}")

        return findings
