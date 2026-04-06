"""Shared helpers for form-based web authentication."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import httpx


DEFAULT_LOGIN_PATHS = [
    "/login",
    "/admin",
    "/wp-login.php",
    "/administrator",
    "/auth/login",
    "/signin",
    "/user/login",
]


@dataclass(frozen=True)
class LoginForm:
    page_url: str
    action_url: str
    username_field: str
    password_field: str
    hidden_fields: dict[str, str]


def extract_login_form(html: str, page_url: str, auth_config: dict | None = None) -> LoginForm | None:
    auth_config = auth_config or {}
    configured_username_field = auth_config.get("username_field")
    configured_password_field = auth_config.get("password_field")
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        user_field = None
        pass_field = None
        hidden_fields: dict[str, str] = {}
        for inp in inputs:
            input_type = (inp.get("type") or "").lower()
            name = inp.get("name")
            lowered_name = (name or "").lower()
            if not name:
                continue
            if input_type == "hidden":
                hidden_fields[name] = inp.get("value", "")
                continue
            if configured_password_field and name == configured_password_field:
                pass_field = name
                continue
            if configured_username_field and name == configured_username_field:
                user_field = name
                continue
            if input_type == "password" or "pass" in lowered_name:
                pass_field = name
                continue
            if input_type in {"text", "email"} or any(
                marker in lowered_name for marker in ("user", "email", "login", "name")
            ):
                user_field = name

        if not user_field or not pass_field:
            continue

        action = form.get("action", "") or page_url
        action_url = urljoin(page_url, action)
        return LoginForm(
            page_url=page_url,
            action_url=action_url,
            username_field=user_field,
            password_field=pass_field,
            hidden_fields=hidden_fields,
        )

    return None


def _normalized_markers(values: list[str] | tuple[str, ...] | None) -> list[str]:
    if not values:
        return []
    return [value.lower() for value in values if value]


def login_successful(response: httpx.Response, auth_config: dict | None = None) -> bool:
    auth_config = auth_config or {}
    body = response.text.lower()
    location = response.headers.get("location", "").lower()
    success_markers = _normalized_markers(auth_config.get("success_markers"))
    failure_markers = _normalized_markers(auth_config.get("failure_markers"))
    success_location_markers = _normalized_markers(auth_config.get("success_location_markers"))
    failure_location_markers = _normalized_markers(auth_config.get("failure_location_markers"))
    success_status_codes = set(auth_config.get("success_status_codes", []) or [])
    failure_status_codes = set(auth_config.get("failure_status_codes", []) or [])

    if response.status_code in failure_status_codes:
        return False
    if response.status_code in success_status_codes:
        return True
    if any(marker in location for marker in failure_location_markers):
        return False
    if any(marker in body for marker in failure_markers):
        return False
    if any(marker in location for marker in success_location_markers):
        return True
    if any(marker in body for marker in success_markers):
        return True

    if response.status_code in (301, 302, 303) and any(
        token in location for token in ("dashboard", "account", "profile", "admin")
    ):
        return True
    if response.status_code in (301, 302, 303) and "login" not in location:
        return True
    return all(token not in body for token in ("invalid", "error", "failed", "incorrect"))


async def submit_login_form(
    client: httpx.AsyncClient,
    form: LoginForm,
    username: str,
    password: str,
    *,
    headers: dict | None = None,
    auth_config: dict | None = None,
) -> httpx.Response:
    auth_config = auth_config or {}
    data = dict(form.hidden_fields)
    data[form.username_field] = username
    data[form.password_field] = password
    data.update(auth_config.get("extra_form_fields", {}) or {})
    return await client.post(form.action_url, data=data, headers=headers)


async def bootstrap_login_from_config(
    client: httpx.AsyncClient,
    auth_config: dict,
    *,
    headers: dict | None = None,
) -> httpx.Response | None:
    bearer_token = auth_config.get("bearer_token")
    if bearer_token:
        client.headers["Authorization"] = f"Bearer {bearer_token}"

    api_key = auth_config.get("api_key")
    api_key_header = auth_config.get("api_key_header")
    if api_key and api_key_header:
        client.headers[api_key_header] = api_key

    bootstrap_headers = auth_config.get("headers", {}) or {}
    if bootstrap_headers:
        client.headers.update(bootstrap_headers)

    bootstrap_cookies = auth_config.get("cookies", {}) or {}
    if bootstrap_cookies:
        for key, value in bootstrap_cookies.items():
            client.cookies.set(key, value)

    login_url = auth_config.get("login_url")
    username = auth_config.get("username")
    password = auth_config.get("password")
    if not login_url or username is None or password is None:
        return None

    login_page = await client.get(login_url, headers=headers)
    form = extract_login_form(login_page.text, str(login_page.url), auth_config=auth_config)
    if not form:
        return None
    return await submit_login_form(
        client,
        form,
        username,
        password,
        headers=headers,
        auth_config=auth_config,
    )
