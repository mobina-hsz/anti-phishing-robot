"""Inspect trust-seal links without treating missing seals as proof of phishing."""

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from analyzer.http_client import Fetcher, FetchError, normalize_url
from analyzer.models import CheckResult, Page, Status

TRUST_HOST = "trustseal.enamad.ir"
SENSITIVE_WORDS = ("درگاه پرداخت", "سامانه ثنا", "سهام عدالت", "ابلاغیه", "شاپرک", "یارانه")


def host_matches(text: str, host: str) -> bool:
    host = host.removeprefix("www.")
    return bool(re.search(r"(?<![\w.-])(?:www\.)?" + re.escape(host) + r"(?![\w.-])", text, re.I))


async def check_enamad(page: Page, fetcher: Fetcher) -> CheckResult:
    """Return heuristic evidence, not an official license or safety certification."""
    soup = BeautifulSoup(page.text, "html.parser")
    text = soup.get_text(" ", strip=True)
    warnings = []
    if urlsplit(page.url).scheme == "http":
        warnings.append("صفحه با HTTP و بدون رمزنگاری دریافت شد؛ این به‌تنهایی اثبات فیشینگ نیست.")
    sensitive = any(word in text for word in SENSITIVE_WORDS)
    base = soup.find("base", href=True)
    base_url = urljoin(page.url, str(base["href"])) if base else page.url
    images = soup.find_all("img", src=re.compile("enamad", re.I))
    links = []
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"])
        if anchor.find("img", src=re.compile("enamad", re.I)) or "trustseal.enamad" in href.lower():
            links.append(href)
    if images and not links:
        warnings.append(
            "تصویر اینماد دیده شد ولی لینک قابل بررسی پیدا نشد؛ ممکن است پیوند با جاوااسکریپت باز شود."
        )
    if not links:
        if sensitive:
            warnings.append(
                "محتوای حساس دیده شد. نبود اینماد در سامانه‌های دولتی الزاماً غیرعادی نیست."
            )
        return CheckResult(
            Status.NOT_DETECTED, "نشانه مشخصی از جعل لینک اینماد پیدا نشد.", tuple(warnings)
        )

    host = urlsplit(page.url).hostname or ""
    inconclusive = False
    verified = False
    if len(set(links)) > 3:
        inconclusive = True
        warnings.append("به دلیل محدودیت منابع، فقط سه لینک متمایز اینماد بررسی شد.")
    for href in list(dict.fromkeys(links))[:3]:
        try:
            seal_url = normalize_url(urljoin(base_url, href))
        except FetchError:
            inconclusive = True
            warnings.append("پیوند نماد قابل دریافت و بررسی نیست.")
            continue
        parsed = urlsplit(seal_url)
        if parsed.hostname != TRUST_HOST:
            return CheckResult(
                Status.SUSPICIOUS,
                "لینک نشان اینماد به میزبان رسمی trustseal.enamad.ir اشاره نمی‌کند.",
                tuple(warnings),
            )
        if parsed.scheme != "https" or parsed.port not in {None, 443}:
            inconclusive = True
            warnings.append("پیوند نماد از HTTPS استاندارد استفاده نمی‌کند.")
            continue
        try:
            seal = await fetcher.get(seal_url, allowed_host=TRUST_HOST)
        except FetchError:
            inconclusive = True
            warnings.append("مرجع اینماد قابل بررسی نبود؛ این خطا اثبات جعل نیست.")
            continue
        seal_text = BeautifulSoup(seal.text, "html.parser").get_text(" ", strip=True).lower()
        # Exact hostname boundaries prevent shop.ir from matching fake-shop.ir or shop.ir.evil.test.
        if host_matches(seal_text, host):
            verified = True
            continue
        domain_field = re.search(
            r"(?:دامنه|آدرس\s*(?:وب\s*)?سایت|website|domain)\s*[:：]?\s*"
            r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})",
            seal_text,
            re.I,
        )
        if domain_field and not host_matches(domain_field.group(1), host):
            return CheckResult(
                Status.SUSPICIOUS,
                "دامنه درج‌شده در صفحه نماد با دامنه این سایت تطابق ندارد.",
                tuple(warnings),
            )
        inconclusive = True
        warnings.append(
            "دامنه سایت در محتوای قابل خواندن مرجع نماد تأیید نشد؛ صفحه ممکن است پویا یا محدود شده باشد."
        )
    if inconclusive:
        return CheckResult(
            Status.INCONCLUSIVE, "بررسی همه پیوندهای اینماد کامل نشد.", tuple(warnings)
        )
    if verified:
        return CheckResult(
            Status.NOT_DETECTED,
            "دامنه در صفحه مرجع نماد دیده شد؛ این به‌تنهایی امنیت کل سایت را تضمین نمی‌کند.",
            tuple(warnings),
        )
    return CheckResult(Status.INCONCLUSIVE, "اعتبار پیوند نماد قابل بررسی نبود.", tuple(warnings))
