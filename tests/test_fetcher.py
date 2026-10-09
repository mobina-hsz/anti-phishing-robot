import asyncio
import socket
from unittest.mock import AsyncMock

import aiohttp
import pytest

from analyzer.http_client import Fetcher, FetchError, PublicResolver, normalize_url
from config import Settings


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://192.168.1.1/",
        "http://localhost/",
        "ftp://example.com/",
        "https://user:pass@example.com/",
        "https://example.com:8080/",
        "https://example.com\\@127.0.0.1/",
        "https://example.com/\nsecret",
        "https://[broken",
        "http://224.0.0.1/",
    ],
)
def test_unsafe_urls_are_rejected(url):
    with pytest.raises(FetchError):
        normalize_url(url)


@pytest.mark.parametrize(
    "url,expected",
    [
        ("www.example.com", "https://www.example.com/"),
        ("HTTPS://EXAMPLE.COM/a?q=1#fragment", "https://example.com/a?q=1"),
        ("https://مثال.ir", "https://xn--mgbh0fb.ir/"),
        ("https://8.8.8.8", "https://8.8.8.8/"),
    ],
)
def test_normalize_valid_urls(url, expected):
    assert normalize_url(url) == expected


async def test_resolver_blocks_mixed_public_private_dns(monkeypatch):
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
    ]
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=records))
    with pytest.raises(FetchError, match="blocked_address"):
        await PublicResolver().resolve("public.example", 443)


async def test_resolver_returns_the_checked_public_address(monkeypatch):
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=records))
    result = await PublicResolver().resolve("public.example", 443)
    assert result[0]["host"] == "8.8.8.8"


class Body:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_chunked(self, size):
        for chunk in self.chunks:
            yield chunk


class Response:
    def __init__(
        self,
        url="https://shop.example/",
        status=200,
        headers=None,
        body=b"<p>hello</p>",
        content_type="text/html",
    ):
        self.url = url
        self.status = status
        self.headers = headers or {}
        self.content = Body([body])
        self.content_type = content_type
        self.charset = "utf-8"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class Session:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


async def test_main_page_is_direct_and_cached():
    fetcher = Fetcher(Settings())
    fetcher.session = Session(Response())
    page = await fetcher.get("https://shop.example/")
    assert await fetcher.get("https://shop.example/") is page
    assert fetcher.session.calls == [("https://shop.example/", {"allow_redirects": False})]


async def test_redirect_to_internal_address_is_blocked_before_second_request():
    fetcher = Fetcher(Settings())
    fetcher.session = Session(Response(status=302, headers={"Location": "http://127.0.0.1/secret"}))
    with pytest.raises(FetchError, match="blocked_address"):
        await fetcher.get("https://shop.example/")
    assert len(fetcher.session.calls) == 1


async def test_seal_redirect_cannot_escape_official_host():
    fetcher = Fetcher(Settings())
    fetcher.session = Session(Response(status=302, headers={"Location": "https://evil.example/"}))
    with pytest.raises(FetchError, match="untrusted_redirect"):
        await fetcher.get("https://trustseal.enamad.ir/", allowed_host="trustseal.enamad.ir")
    assert len(fetcher.session.calls) == 1


@pytest.mark.parametrize(
    "response,code",
    [
        (Response(status=403), "http_403"),
        (Response(body=b"x" * 5000), "response_too_large"),
        (Response(content_type="application/octet-stream"), "unsupported_content_type"),
        (Response(body=b""), "empty_response"),
        (TimeoutError(), "timeout"),
        (aiohttp.ClientConnectionError(), "network_error"),
        (Response(headers={"Content-Encoding": "gzip"}), "unsupported_encoding"),
    ],
)
async def test_fetch_errors_have_stable_codes(response, code):
    fetcher = Fetcher(Settings(max_response_bytes=4096))
    fetcher.session = Session(response)
    with pytest.raises(FetchError, match=code):
        await fetcher.get("https://shop.example/")
    assert fetcher.errors == [code]


async def test_tls_is_verified_and_environment_proxy_is_ignored():
    async with Fetcher(Settings()) as fetcher:
        assert fetcher.session.connector._ssl is True
        assert fetcher.session.trust_env is False
        assert isinstance(fetcher.session.cookie_jar, aiohttp.DummyCookieJar)
