import urllib.parse
import socket
import ssl
from datetime import datetime, timezone

import aiohttp


KNOWN_SERVICES = {
    "google.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "linkedin.com",
    "netflix.com"
}


def is_known_service(domain):
    """بررسی می‌کند دامنه متعلق به یک سرویس شناخته‌شده است یا نه."""

    return any(
        domain == service or domain.endswith("." + service)
        for service in KNOWN_SERVICES
    )


def get_ip_information(domain):
    """دریافت IP دامنه."""

    try:
        ip_address = socket.gethostbyname(domain)

        return {
            "ip_address": ip_address,
            "dns_resolved": True,
            "error": None
        }

    except socket.gaierror:
        return {
            "ip_address": None,
            "dns_resolved": False,
            "error": "DNS resolution failed"
        }


def get_tls_information(domain):
    """بررسی HTTPS و اطلاعات گواهی TLS."""

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                return {
                    "https_available": True,
                    "certificate_subject": str(
                        certificate.get("subject", "")
                    ),
                    "certificate_issuer": str(
                        certificate.get("issuer", "")
                    ),
                    "error": None
                }

    except Exception as e:

        return {
            "https_available": False,
            "certificate_subject": None,
            "certificate_issuer": None,
            "error": f"TLS error: {type(e).__name__}"
        }


async def get_http_information(url):
    """دریافت اطلاعات HTTP و Headerهای سایت."""

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        )
    }

    try:

        timeout = aiohttp.ClientTimeout(total=5)

        async with aiohttp.ClientSession(
            timeout=timeout
        ) as session:

            async with session.head(
                url,
                headers=headers,
                allow_redirects=True
            ) as response:

                response_headers = response.headers

                server = response_headers.get(
                    "Server",
                    ""
                ).lower()

                is_cloudflare = (
                    "cloudflare" in server
                    or "cf-ray" in response_headers
                )

                return {
                    "status_code": response.status,
                    "server": server,
                    "is_cloudflare": is_cloudflare,
                    "final_url": str(response.url),
                    "redirected": str(response.url) != url,
                    "error": None
                }

    except aiohttp.ClientError as e:

        return {
            "status_code": None,
            "server": "",
            "is_cloudflare": False,
            "final_url": url,
            "redirected": False,
            "error": f"HTTP error: {type(e).__name__}"
        }

    except Exception as e:

        return {
            "status_code": None,
            "server": "",
            "is_cloudflare": False,
            "final_url": url,
            "redirected": False,
            "error": f"Unexpected error: {type(e).__name__}"
        }


async def get_domain_age(domain):
    """
    دریافت تاریخ ثبت دامنه از RDAP
    و محاسبه قدمت دامنه.
    """

    rdap_url = f"https://rdap.org/domain/{domain}"

    try:

        timeout = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(
            timeout=timeout
        ) as session:

            async with session.get(rdap_url) as response:

                if response.status != 200:

                    return {
                        "registration_date": None,
                        "domain_age_days": None,
                        "domain_age_category": "unknown",
                        "domain_age_score": 0,
                        "error": f"RDAP status: {response.status}"
                    }

                data = await response.json()

        registration_date = None

        # پیدا کردن event مربوط به registration
        for event in data.get("events", []):

            if event.get("eventAction") == "registration":
                registration_date = event.get("eventDate")
                break

        if not registration_date:

            return {
                "registration_date": None,
                "domain_age_days": None,
                "domain_age_category": "unknown",
                "domain_age_score": 0,
                "error": "Registration date not found"
            }

        # تبدیل تاریخ RDAP به datetime
        registration_datetime = datetime.fromisoformat(
            registration_date.replace("Z", "+00:00")
        )

        now = datetime.now(timezone.utc)

        age_days = (
            now - registration_datetime
        ).days

        # دسته‌بندی قدمت دامنه
        if age_days < 7:

            category = "totally suspic"
            score = 40

        elif age_days < 30:

            category = "very suspic"
            score = 30

        elif age_days < 90:

            category = "suspic"
            score = 20

        elif age_days < 180:

            category = "relatively suspic"
            score = 10

        elif age_days > 2190 :
            category = "not suspic at all"
            score = 0
        else:
            category = "low suspic"
            score = 5

        return {
            "registration_date": registration_date,
            "domain_age_days": age_days,
            "domain_age_category": category,
            "domain_age_score": score,
            "error": None
        }

    except Exception as e:

        return {
            "registration_date": None,
            "domain_age_days": None,
            "domain_age_category": "unknown",
            "domain_age_score": 0,
            "error": f"RDAP error: {type(e).__name__}"
        }


def calculate_suspicion(result):
    """
    محاسبه امتیاز کلی مشکوک بودن بر اساس featureهای زیرساختی.
    """

    score = result["domain_age_score"]
    reasons = []

    # -------------------------
    # Domain Age
    # -------------------------

    if result["domain_age_days"] is not None:

        if result["domain_age_days"] < 7:
            reasons.append(
                "دامنه کمتر از یک هفته قدمت دارد."
            )

        elif result["domain_age_days"] < 30:
            reasons.append(
                "دامنه کمتر از یک ماه قدمت دارد."
            )

        elif result["domain_age_days"] < 90:
            reasons.append(
                "دامنه کمتر از سه ماه قدمت دارد."
            )

        elif result["domain_age_days"] < 180:
            reasons.append(
                "دامنه کمتر از شش ماه قدمت دارد."
            )

    # -------------------------
    # DNS
    # -------------------------

    if not result["dns_resolved"]:

        score += 20

        reasons.append(
            "دامنه به IP قابل دسترسی resolve نشد."
        )

    # -------------------------
    # HTTPS
    # -------------------------

    if not result["https_available"]:

        score += 15

        reasons.append(
            "HTTPS یا گواهی TLS معتبر در دسترس نیست."
        )

    # -------------------------
    # Redirect
    # -------------------------

    if result["redirected"]:

        score += 5

        reasons.append(
            "URL به آدرس دیگری redirect شد."
        )

    # -------------------------
    # HTTP Status
    # -------------------------

    if result["status_code"] is not None:

        if result["status_code"] >= 400:

            score += 10

            reasons.append(
                f"پاسخ HTTP غیرعادی است: "
                f"{result['status_code']}"
            )

    # -------------------------
    # Known Service
    # -------------------------

    if result["known_service"]:

        score = max(0, score - 30)

        reasons.append(
            "دامنه متعلق به یک سرویس شناخته‌شده است."
        )

    # -------------------------
    # Cloudflare
    # -------------------------

    if result["is_cloudflare"]:

        reasons.append(
            "سایت از Cloudflare استفاده می‌کند؛ "
            "این مورد به‌تنهایی نشانه سالم یا مخرب بودن نیست."
        )
        score -= 20

    # محدود کردن score به بازه 0 تا 100
    score = min(score, 100)

    # تبدیل score به سطح ریسک
    if score >= 70:

        risk_level = "totally suspic"

    elif score >= 40:

        risk_level = "suspic"

    elif score >= 20:

        risk_level = "relatively suspic"

    else:

        risk_level = "low suspic"

    return score, risk_level, reasons


async def check_infrastructure(url):
    """
    جمع‌آوری اطلاعات زیرساختی و
    محاسبه میزان مشکوک بودن URL.
    """

    parsed = urllib.parse.urlparse(url)

    domain = parsed.hostname

    if not domain:

        return {
            "url": url,
            "valid_url": False,
            "error": "Invalid URL"
        }

    domain = domain.lower()

    # نتیجه اولیه
    result = {
        "url": url,
        "domain": domain,
        "valid_url": True,

        "known_service": is_known_service(domain),

        "ip_address": None,
        "dns_resolved": False,

        "https_available": False,
        "certificate_subject": None,
        "certificate_issuer": None,

        "registration_date": None,
        "domain_age_days": None,
        "domain_age_category": "unknown",
        "domain_age_score": 0,

        "status_code": None,
        "server": "",
        "is_cloudflare": False,

        "final_url": url,
        "redirected": False,

        "suspicion_score": 0,
        "risk_level": "unknown",
        "suspicion_reasons": [],

        "error": None
    }

    # -------------------------
    # DNS / IP
    # -------------------------

    ip_info = get_ip_information(domain)
    result.update(ip_info)

    # -------------------------
    # TLS
    # -------------------------

    tls_info = get_tls_information(domain)
    result.update(tls_info)

    # -------------------------
    # HTTP
    # -------------------------

    http_info = await get_http_information(url)
    result.update(http_info)

    # -------------------------
    # Domain Age / RDAP
    # -------------------------

    domain_age_info = await get_domain_age(domain)
    result.update(domain_age_info)

    # -------------------------
    # Suspicion Score
    # -------------------------

    score, risk_level, reasons = calculate_suspicion(result)

    result["suspicion_score"] = score
    result["risk_level"] = risk_level
    result["suspicion_reasons"] = reasons

    return result