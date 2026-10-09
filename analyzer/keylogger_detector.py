"""Conservative static signals for possible browser input exfiltration."""

import re
from bisect import bisect_right
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from analyzer.http_client import Fetcher, FetchError
from analyzer.models import CheckResult, Page, Status

LISTENER = re.compile(
    r"(?:addEventListener\s*\(\s*|\.(?:on|bind)\s*\(\s*)['\"]"
    r"(?:keydown|keyup|keypress|input)['\"]\s*,",
    re.I,
)
PROPERTY_HANDLER = re.compile(r"\bon(?:keydown|keyup|keypress|input)\s*=", re.I)
NETWORK = re.compile(
    r"\bfetch\s*\(|\bsendBeacon\s*\(|\.\s*send\s*\(|\$\s*\.\s*(?:ajax|post)\s*\(", re.I
)
INPUT_VALUE = re.compile(r"\.\s*(?:value|key|keyCode|which)\b|\bFormData\s*\(", re.I)
PACKER = re.compile(
    r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)", re.I
)
TELEGRAM = re.compile(r"api\s*\.\s*telegram\s*\.\s*org\s*/\s*bot", re.I)
STRINGS = re.compile(r"(['\"`])(?:\\.|(?!\1)[\s\S])*?\1")


def code_matches(pattern: re.Pattern, source: str):
    """Ignore matches inside quoted code examples or string data."""
    spans = [match.span() for match in STRINGS.finditer(source)]
    starts = [span[0] for span in spans]
    for match in pattern.finditer(source):
        index = bisect_right(starts, match.start()) - 1
        if index < 0 or match.start() >= spans[index][1]:
            yield match


def strip_comments(source: str) -> str:
    """Remove comments while preserving strings and their escaped characters."""
    tokens = re.compile(r"(['\"`])(?:\\.|(?!\1)[\s\S])*?\1|/\*[\s\S]*?\*/|//[^\r\n]*")
    return tokens.sub(lambda match: match.group(0) if match.group(0)[0] in "'\"`" else " ", source)


def callback_body(source: str, start: int) -> str:
    """Extract a nearby braced callback; named callbacks and expression arrows are unsupported."""
    tail = source[start:]
    prefix = re.match(
        r"\s*(?:async\s+)?(?:function(?:\s+[\w$]+)?\s*\([^)]*\)|\([^)]*\)\s*=>|[\w$]+\s*=>)\s*\{",
        tail,
    )
    if not prefix:
        return ""
    opening = start + prefix.end() - 1
    depth = 0
    quote = None
    escaped = False
    for index in range(opening, len(source)):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    return ""


def analyze_script(source: str) -> tuple[bool, list[str]]:
    """Require multiple signals; obfuscation or exposed tokens alone are warnings."""
    source = strip_comments(source)
    warnings = []
    if TELEGRAM.search(source):
        warnings.append("آدرس API تلگرام در جاوااسکریپت دیده شد؛ به‌تنهایی نشانه کی‌لاگر نیست.")
    handlers = list(code_matches(LISTENER, source)) + list(code_matches(PROPERTY_HANDLER, source))
    for match in handlers:
        body = callback_body(source, match.end())
        if next(code_matches(NETWORK, body), None) and next(code_matches(INPUT_VALUE, body), None):
            return True, [
                "در یک callback ورودی یا کیبورد، خواندن مقدار و ارسال شبکه دیده شد؛ احتمال خروج اطلاعات وجود دارد."
            ]
    if (
        PACKER.search(source)
        or len(re.findall(r"\\x[0-9a-f]{2}", source, re.I)) > 20
        or len(set(re.findall(r"_0x[0-9a-f]+", source, re.I))) > 10
    ):
        warnings.append("جاوااسکریپت مبهم دیده شد؛ مبهم‌سازی به‌تنهایی اثبات بدافزار نیست.")
    return False, warnings


async def check_keylogger(page: Page, fetcher: Fetcher) -> CheckResult:
    """Read inline handlers and a bounded number of external scripts, without execution."""
    soup = BeautifulSoup(page.text, "html.parser")
    warnings = []
    partial = False
    sources = []
    external = []
    base = soup.find("base", href=True)
    base_url = urljoin(page.url, str(base["href"])) if base else page.url
    for script in soup.find_all("script"):
        script_type = str(script.get("type", "")).lower().strip()
        if script_type not in {"", "module", "text/javascript", "application/javascript"}:
            continue
        if script.get("src"):
            external.append(urljoin(base_url, str(script["src"])))
        else:
            sources.append(script.get_text())
    for tag in soup.find_all(True):
        for attr in ("onkeydown", "onkeyup", "onkeypress", "oninput"):
            if tag.get(attr):
                # Inline HTML handlers execute in an input event context.
                sources.append(f"oninput = function(event) {{ {tag[attr]} }}")
    for source in sources:
        suspicious, notes = analyze_script(source)
        warnings.extend(notes)
        if suspicious:
            return CheckResult(Status.SUSPICIOUS, notes[0], tuple(dict.fromkeys(warnings[0:-1])))
    external = list(dict.fromkeys(external))
    if len(external) > fetcher.settings.max_external_scripts:
        partial = True
        warnings.append("بعضی فایل‌های جاوااسکریپت به دلیل محدودیت تعداد بررسی نشدند.")
    for script_url in external[: fetcher.settings.max_external_scripts]:
        try:
            script_page = await fetcher.get(script_url, kind="script")
        except FetchError:
            partial = True
            warnings.append("حداقل یک فایل جاوااسکریپت قابل دریافت نبود.")
            continue
        suspicious, notes = analyze_script(script_page.text)
        warnings.extend(notes)
        if suspicious:
            return CheckResult(Status.SUSPICIOUS, notes[0], tuple(dict.fromkeys(warnings[0:-1])))
    reason = "در بخش‌های قابل بررسی، الگوی مشخصی از خروج اطلاعات ورودی پیدا نشد."
    if partial:
        reason = "بررسی جاوااسکریپت کامل نشد؛ نتیجه قطعی قابل ارائه نیست."
    return CheckResult(
        Status.INCONCLUSIVE if partial else Status.NOT_DETECTED,
        reason,
        tuple(dict.fromkeys(warnings)),
    )
