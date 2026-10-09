"""Fetch the main page once and preserve partial evidence on scan timeouts."""

import asyncio
import logging
import time
from urllib.parse import urlsplit

from analyzer.enamad_checker import check_enamad
from analyzer.http_client import Fetcher, FetchError, normalize_url
from analyzer.keylogger_detector import check_keylogger
from analyzer.models import CheckResult, ScanResult, Status
from config import Settings

logger = logging.getLogger(__name__)


async def scan_url(url: str, settings: Settings) -> ScanResult:
    started = time.monotonic()
    unknown = CheckResult(
        Status.INCONCLUSIVE, "بررسی کامل نشد؛ امنیت یا فیشینگ بودن قابل تأیید نیست."
    )
    phishing = keylogger = unknown
    errors = []
    fetcher = Fetcher(settings)
    try:
        url = normalize_url(url)
        async with asyncio.timeout(settings.scan_timeout):
            async with fetcher:
                page = await fetcher.get(url)
                # Scan local scripts first so a slow trust-seal server cannot hide obvious evidence.
                keylogger = await check_keylogger(page, fetcher)
                phishing = await check_enamad(page, fetcher)
    except FetchError as exc:
        errors.append(exc.code)
    except TimeoutError:
        errors.append("scan_timeout")
    except Exception as exc:
        # Never log arbitrary exception text: it can contain URLs, tokens, or page content.
        logger.error("Unexpected scan error: %s", type(exc).__name__)
        errors.append("internal_error")
    errors.extend(fetcher.errors)
    elapsed = int((time.monotonic() - started) * 1000)
    result = ScanResult(url, phishing, keylogger, elapsed, tuple(dict.fromkeys(errors)))
    try:
        host = urlsplit(url).hostname or "invalid"
    except ValueError:
        host = "invalid"
    logger.info(
        "Scan completed host=%s status=%s elapsed_ms=%s errors=%s",
        host,
        result.status,
        elapsed,
        ",".join(result.errors) or "none",
    )
    return result
