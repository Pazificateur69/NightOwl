"""Tests for traffic analyzer safety defaults."""

import asyncio

import httpx

from nightowl.models.target import Target
from nightowl.modules.web.proxy_interceptor import TrafficAnalyzerPlugin


def test_traffic_analyzer_is_passive_by_default():
    async def scenario():
        plugin = TrafficAnalyzerPlugin()
        requests = []
        html = """
        <html>
          <body>
            <form method="POST" action="/submit">
              <input name="email" value="" />
            </form>
          </body>
        </html>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request.method)
            if request.method == "GET":
                return httpx.Response(
                    200,
                    text=html,
                    headers={"content-type": "text/html"},
                )
            return httpx.Response(200, text="posted")

        transport = httpx.MockTransport(handler)

        def fake_client(**_kwargs):
            return httpx.AsyncClient(transport=transport, base_url="http://example.test")

        plugin.create_http_client = fake_client  # type: ignore[method-assign]
        findings = await plugin.run(Target(host="http://example.test"))
        assert requests == ["GET"]
        summary = findings[-1]
        assert summary.metadata["forms_detected"] == 1
        assert summary.metadata["active_form_submission"] is False

    asyncio.run(scenario())
