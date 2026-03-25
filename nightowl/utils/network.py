"""Network utility helpers."""

import ipaddress
import re
import socket
from urllib.parse import urlparse

import httpx


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_domain(host: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", host))


def resolve_host(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


async def get_http_response(url: str, **kwargs) -> httpx.Response | None:
    timeout = kwargs.pop("timeout", 10)
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=timeout
        ) as client:
            return await client.get(url, **kwargs)
    except Exception:
        return None


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")


def extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc or parsed.path.split("/")[0]
