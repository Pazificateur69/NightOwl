"""Shared web attack-surface discovery helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup


@dataclass(frozen=True)
class DiscoveredForm:
    page_url: str
    action_url: str
    method: str
    params: dict[str, str]
    attackable_params: list[str]


@dataclass(frozen=True)
class WebDiscoveryResult:
    visited_pages: list[str]
    urls_with_params: list[str]
    forms: list[DiscoveredForm]


def _normalize_page_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    parsed = urlparse(candidate)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname == base.hostname
        and (parsed.port or (443 if parsed.scheme == "https" else 80))
        == (base.port or (443 if base.scheme == "https" else 80))
    )


def _extract_form_fields(
    form,
    *,
    default_value_fn,
) -> tuple[dict[str, str], list[str]]:
    params: dict[str, str] = {}
    attackable_params: list[str] = []
    for field in form.find_all(["input", "textarea", "select"]):
        name = (field.get("name") or "").strip()
        if not name:
            continue
        input_type = (field.get("type") or "text").lower()
        if input_type in {"submit", "button", "reset", "image", "file"}:
            continue
        params[name] = field.get("value") or default_value_fn(name)
        if input_type not in {"hidden", "checkbox", "radio"} and " " not in name:
            attackable_params.append(name)
    return params, attackable_params


def _discover_from_html(
    html: str,
    page_url: str,
    *,
    default_value_fn,
    max_forms: int,
) -> tuple[list[str], list[DiscoveredForm]]:
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    forms: list[DiscoveredForm] = []

    for a in soup.find_all("a", href=True):
        absolute = _normalize_page_url(urljoin(page_url, a["href"]))
        links.append(absolute)

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        action_url = _normalize_page_url(urljoin(page_url, action) if action else page_url)
        method = (form.get("method") or "get").lower()
        if method not in {"get", "post"}:
            continue
        params, attackable_params = _extract_form_fields(
            form,
            default_value_fn=default_value_fn,
        )
        if not attackable_params:
            continue
        forms.append(
            DiscoveredForm(
                page_url=page_url,
                action_url=action_url,
                method=method,
                params=params,
                attackable_params=attackable_params,
            )
        )
        if len(forms) >= max_forms:
            break

    return links, forms


async def discover_web_attack_surface(
    client: httpx.AsyncClient,
    base_url: str,
    *,
    default_value_fn,
    max_depth: int = 1,
    max_pages: int = 8,
    max_urls_with_params: int = 12,
    max_forms: int = 12,
    request_headers: dict | None = None,
    wait_hook=None,
) -> WebDiscoveryResult:
    """Crawl a small same-origin slice of an app and extract attackable URLs/forms."""
    visited_pages: list[str] = []
    urls_with_params: list[str] = []
    forms: list[DiscoveredForm] = []

    seen_pages: set[str] = set()
    seen_param_urls: set[str] = set()
    seen_forms: set[tuple[str, str, tuple[str, ...]]] = set()
    queue: list[tuple[str, int]] = [(_normalize_page_url(base_url), 0)]

    while queue and len(visited_pages) < max_pages:
        current_url, depth = queue.pop(0)
        if current_url in seen_pages or depth > max_depth:
            continue
        if not _same_origin(base_url, current_url):
            continue
        seen_pages.add(current_url)

        try:
            response = await client.get(current_url, headers=request_headers)
        except httpx.RequestError:
            if wait_hook:
                await wait_hook()
            continue
        finally:
            if wait_hook:
                await wait_hook()

        content_type = response.headers.get("content-type", "").lower()
        parsed_response_url = _normalize_page_url(str(response.url))
        visited_pages.append(parsed_response_url)

        if parse_qs(urlparse(parsed_response_url).query) and parsed_response_url not in seen_param_urls:
            seen_param_urls.add(parsed_response_url)
            urls_with_params.append(parsed_response_url)

        if "html" not in content_type and "<html" not in response.text[:200].lower():
            continue

        links, page_forms = _discover_from_html(
            response.text,
            parsed_response_url,
            default_value_fn=default_value_fn,
            max_forms=max_forms,
        )
        for link in links:
            if not _same_origin(base_url, link):
                continue
            if parse_qs(urlparse(link).query) and link not in seen_param_urls:
                seen_param_urls.add(link)
                urls_with_params.append(link)
                if len(urls_with_params) >= max_urls_with_params:
                    break
            if depth < max_depth and link not in seen_pages:
                queue.append((link, depth + 1))
        if len(urls_with_params) >= max_urls_with_params:
            urls_with_params = urls_with_params[:max_urls_with_params]

        for form in page_forms:
            form_key = (
                form.method,
                form.action_url,
                tuple(sorted(form.attackable_params)),
            )
            if form_key in seen_forms:
                continue
            seen_forms.add(form_key)
            forms.append(form)
            if len(forms) >= max_forms:
                break

        if len(forms) >= max_forms and len(urls_with_params) >= max_urls_with_params:
            break

    return WebDiscoveryResult(
        visited_pages=visited_pages,
        urls_with_params=urls_with_params[:max_urls_with_params],
        forms=forms[:max_forms],
    )


def form_to_legacy_dict(form: DiscoveredForm, *, param_key: str = "attackable_params") -> dict:
    payload = asdict(form)
    payload["url"] = payload.pop("action_url")
    payload[param_key] = payload.pop("attackable_params")
    return payload
