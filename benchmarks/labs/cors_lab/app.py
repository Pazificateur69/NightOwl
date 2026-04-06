"""Small local benchmark lab for CORS misconfiguration checks."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


SAFE_ORIGIN = "https://myapp.local"


class CORSLabHandler(BaseHTTPRequestHandler):
    server_version = "NightOwlCORSLab/1.0"

    def log_message(self, format: str, *args) -> None:
        return

    def _send(
        self,
        body: str,
        *,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _route_headers(self, route: str, origin: str, method: str) -> dict[str, str]:
        if route == "/wildcard-credentials":
            return {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST",
            }
        if route == "/reflect-credentials":
            allow_origin = SAFE_ORIGIN if origin == "null" else (origin or SAFE_ORIGIN)
            return {
                "Access-Control-Allow-Origin": allow_origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST",
            }
        if route == "/null-origin":
            return {
                "Access-Control-Allow-Origin": "null" if origin == "null" else SAFE_ORIGIN,
                "Access-Control-Allow-Methods": "GET, POST",
            }
        if route == "/dangerous-methods":
            if method == "OPTIONS":
                allow_origin = SAFE_ORIGIN if origin == "null" else (origin or SAFE_ORIGIN)
                return {
                    "Access-Control-Allow-Origin": allow_origin,
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH",
                }
            return {
                "Access-Control-Allow-Origin": SAFE_ORIGIN,
                "Access-Control-Allow-Methods": "GET, POST",
            }
        if route == "/allowlist":
            headers = {"Access-Control-Allow-Methods": "GET"}
            if origin == SAFE_ORIGIN:
                headers["Access-Control-Allow-Origin"] = SAFE_ORIGIN
            return headers
        return {}

    def do_OPTIONS(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        origin = self.headers.get("Origin", "")
        headers = self._route_headers(parsed.path, origin, "OPTIONS")
        self._send("", extra_headers=headers)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path
        origin = self.headers.get("Origin", "")
        headers = self._route_headers(route, origin, "GET")

        if route == "/":
            self._send(
                """
                <html><body>
                <h1>NightOwl CORS Lab</h1>
                <ul>
                    <li><a href="/wildcard-credentials">/wildcard-credentials</a></li>
                    <li><a href="/reflect-credentials">/reflect-credentials</a></li>
                    <li><a href="/null-origin">/null-origin</a></li>
                    <li><a href="/dangerous-methods">/dangerous-methods</a></li>
                    <li><a href="/allowlist">/allowlist</a></li>
                </ul>
                </body></html>
                """,
                extra_headers=headers,
            )
            return

        if route in {
            "/wildcard-credentials",
            "/reflect-credentials",
            "/null-origin",
            "/dangerous-methods",
            "/allowlist",
        }:
            self._send(f"<html><body><p>{route}</p></body></html>", extra_headers=headers)
            return

        self._send("<html><body>Not found</body></html>", status=404)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), CORSLabHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
