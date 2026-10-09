import socket

from aiohttp import web
from aiohttp.test_utils import TestServer

from analyzer.http_client import PublicResolver
from analyzer.models import Status
from analyzer.scanner import scan_url
from config import Settings


async def test_real_http_redirect_script_and_scanner_transport(monkeypatch):
    """A test-only resolver routes a fixture hostname to an isolated local HTTP server."""
    requested = []

    async def start(request):
        requested.append(request.path)
        raise web.HTTPFound("/landing")

    async def landing(request):
        requested.append(request.path)
        return web.Response(
            text='<script src="/assets/capture.js"></script>', content_type="text/html"
        )

    async def script(request):
        requested.append(request.path)
        return web.Response(
            text='field.oninput = e => {fetch("/collect", {body:e.target.value});};',
            content_type="application/javascript",
        )

    app = web.Application()
    app.router.add_get("/", start)
    app.router.add_get("/landing", landing)
    app.router.add_get("/assets/capture.js", script)
    server = TestServer(app)
    await server.start_server()

    async def fixture_resolver(self, host, port=0, family=socket.AF_INET):
        assert host == "fixture.example"
        return [
            {
                "hostname": host,
                "host": "127.0.0.1",
                "port": server.port,
                "family": socket.AF_INET,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    monkeypatch.setattr(PublicResolver, "resolve", fixture_resolver)
    try:
        result = await scan_url("http://fixture.example/", Settings())
        assert result.status == Status.SUSPICIOUS
        assert result.keylogger.status == Status.SUSPICIOUS
        assert not result.errors
        assert requested == ["/", "/landing", "/assets/capture.js"]
        assert "/collect" not in requested
    finally:
        await server.close()
