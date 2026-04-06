"""Small local benchmark lab for XSS and SQLi checks."""

from __future__ import annotations

import html
import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def _query_value(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key, [default])
    return values[0] if values else default


def _sqlite_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
    conn.executemany(
        "INSERT INTO products(name) VALUES (?)",
        [("apple",), ("banana",), ("nightowl",)],
    )
    conn.commit()
    return conn


class LabHandler(BaseHTTPRequestHandler):
    server_version = "NightOwlLab/1.0"

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, body: str, *, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        route = parsed.path

        if route == "/":
            self._send(
                """
                <html><body>
                <h1>NightOwl Local Benchmark Lab</h1>
                <ul>
                    <li><a href="/xss/reflected?q=test">/xss/reflected</a></li>
                    <li><a href="/xss/escaped?q=test">/xss/escaped</a></li>
                    <li><a href="/xss/json?q=test">/xss/json</a></li>
                    <li><a href="/xss/comment?q=test">/xss/comment</a></li>
                    <li><a href="/xss/attr?q=test">/xss/attr</a></li>
                    <li><a href="/sql/error?q=apple">/sql/error</a></li>
                    <li><a href="/sql/time?q=apple">/sql/time</a></li>
                </ul>
                </body></html>
                """
            )
            return

        if route == "/robots.txt":
            self._send("User-agent: *\nDisallow: /admin\n", content_type="text/plain; charset=utf-8")
            return

        if route == "/xss/reflected":
            q = _query_value(query, "q", "")
            self._send(f"<html><body><div>Search results for: {q}</div></body></html>")
            return

        if route == "/xss/escaped":
            q = html.escape(_query_value(query, "q", ""))
            self._send(f"<html><body><div>Search results for: {q}</div></body></html>")
            return

        if route == "/xss/json":
            q = _query_value(query, "q", "")
            self._send(
                json.dumps({"query": q, "results": ["apple", "banana"]}),
                content_type="application/json; charset=utf-8",
            )
            return

        if route == "/xss/comment":
            q = _query_value(query, "q", "")
            self._send(f"<html><body><!-- {q} --><p>Comment sink</p></body></html>")
            return

        if route == "/xss/attr":
            q = html.escape(_query_value(query, "q", ""), quote=True)
            self._send(f'<html><body><div data-q="{q}">Attribute sink</div></body></html>')
            return

        if route == "/sql/error":
            q = _query_value(query, "q", "apple")
            conn = _sqlite_connection()
            try:
                sql = f"SELECT id, name FROM products WHERE name = '{q}'"
                rows = conn.execute(sql).fetchall()
                self._send(
                    "<html><body><h1>Results</h1><pre>{}</pre></body></html>".format(html.escape(str(rows)))
                )
            except sqlite3.Error as exc:
                self._send(
                    f"<html><body>sqlite_error: {html.escape(str(exc))}</body></html>",
                    status=500,
                )
            finally:
                conn.close()
            return

        if route == "/sql/time":
            q = _query_value(query, "q", "apple")
            lowered = q.lower()
            if any(token in lowered for token in ("sleep(", "waitfor delay", "pg_sleep(", "benchmark(")):
                time.sleep(5)
            self._send(f"<html><body><p>Checked query: {html.escape(q)}</p></body></html>")
            return

        self._send("<html><body>Not found</body></html>", status=404)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), LabHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
