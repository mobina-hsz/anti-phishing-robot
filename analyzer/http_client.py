"""Direct HTTP requests with verified TLS, public-only DNS, and bounded bodies."""

import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
from aiohttp.abc import AbstractResolver

from analyzer.models import Page
from config import Settings


class FetchError(Exception):
    """A stable, secret-free error code suitable for monitoring."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 2048 or any(ord(c) < 33 for c in value) or "\\" in value:
        raise FetchError("invalid_url")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise FetchError("invalid_url")
        if parsed.username is not None or parsed.password is not None:
            raise FetchError("credentials_in_url")
        host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        if len(host) > 253:
            raise FetchError("invalid_host")
        port = parsed.port
        if port not in {None, 80, 443}:
            raise FetchError("blocked_port")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or any(not label or len(label) > 63 for label in host.split(".")):
                raise FetchError("invalid_host")
            if any(not (char.isalnum() or char in ".-") for char in host):
                raise FetchError("invalid_host")
        else:
            if not public_ip(host):
                raise FetchError("blocked_address")
        authority = f"[{host}]" if ":" in host else host
        if port is not None:
            authority += f":{port}"
        return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError) as exc:
        raise FetchError("invalid_url") from exc


class PublicResolver(AbstractResolver):
    """Validate and return the same DNS answers used by the TCP connector."""

    async def resolve(self, host, port=0, family=socket.AF_INET):
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                host, port, family=family, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            raise FetchError("dns_error") from exc
        if not records or any(not public_ip(record[4][0]) for record in records):
            raise FetchError("blocked_address")
        return [
            {
                "hostname": host,
                "host": address[0],
                "port": address[1],
                "family": af,
                "proto": proto,
                "flags": socket.AI_NUMERICHOST,
            }
            for af, _, proto, _, address in records
        ]

    async def close(self):
        pass


class Fetcher:
    """One cookie-free connection pool per scan, shared by both analyzers."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.session = None
        self.errors: list[str] = []
        self.cache: dict[tuple[str, str], Page] = {}

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False, limit=4),
            timeout=aiohttp.ClientTimeout(total=self.settings.request_timeout, connect=5),
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False,
            headers={
                "User-Agent": "IranPhishingRadar/2.0 (static analysis)",
                "Accept-Encoding": "identity",
            },
            auto_decompress=False,
        )
        return self

    async def __aexit__(self, *args):
        await self.session.close()

    async def get(self, url: str, kind: str = "html", allowed_host: str | None = None) -> Page:
        try:
            return await self._get(url, kind, allowed_host)
        except FetchError as exc:
            self.errors.append(exc.code)
            raise

    async def _get(self, url: str, kind: str, allowed_host: str | None) -> Page:
        current = normalize_url(url)
        cache_key = (current, kind)
        if cache_key in self.cache:
            page = self.cache[cache_key]
            if allowed_host and (
                urlsplit(page.url).hostname != allowed_host or urlsplit(page.url).scheme != "https"
            ):
                raise FetchError("untrusted_redirect")
            return page
        try:
            # Every redirect is revalidated, including redirects from trust seals and scripts.
            async with asyncio.timeout(self.settings.request_timeout):
                for _ in range(6):
                    current = normalize_url(current)
                    if allowed_host and (
                        urlsplit(current).hostname != allowed_host
                        or urlsplit(current).scheme != "https"
                    ):
                        raise FetchError("untrusted_redirect")
                    async with self.session.get(current, allow_redirects=False) as response:
                        if response.status in {301, 302, 303, 307, 308}:
                            location = response.headers.get("Location")
                            if not location:
                                raise FetchError("invalid_redirect")
                            current = urljoin(current, location)
                            continue
                        if response.status != 200:
                            raise FetchError(f"http_{response.status}")
                        content_type = response.content_type.lower()
                        accepted = {"text/html", "application/xhtml+xml", "text/plain"}
                        if kind == "script":
                            accepted = {
                                "application/javascript",
                                "text/javascript",
                                "application/x-javascript",
                                "text/plain",
                            }
                        if content_type not in accepted:
                            raise FetchError("unsupported_content_type")
                        if (
                            response.headers.get("Content-Encoding", "identity").lower()
                            != "identity"
                        ):
                            raise FetchError("unsupported_encoding")
                        body = bytearray()
                        async for chunk in response.content.iter_chunked(16384):
                            body.extend(chunk)
                            if len(body) > self.settings.max_response_bytes:
                                raise FetchError("response_too_large")
                        try:
                            text = body.decode(response.charset or "utf-8", errors="replace")
                        except LookupError:
                            text = body.decode("utf-8", errors="replace")
                        if not text.strip():
                            raise FetchError("empty_response")
                        page = Page(str(response.url), text, content_type)
                        self.cache[cache_key] = page
                        return page
                raise FetchError("too_many_redirects")
        except FetchError:
            raise
        except TimeoutError as exc:
            raise FetchError("timeout") from exc
        except aiohttp.ClientConnectorCertificateError as exc:
            raise FetchError("tls_error") from exc
        except aiohttp.ClientSSLError as exc:
            raise FetchError("tls_error") from exc
        except (aiohttp.ClientError, OSError) as exc:
            raise FetchError("network_error") from exc
