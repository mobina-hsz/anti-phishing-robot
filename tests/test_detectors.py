from types import SimpleNamespace

import pytest

from analyzer.enamad_checker import check_enamad, host_matches
from analyzer.http_client import FetchError
from analyzer.keylogger_detector import analyze_script, check_keylogger, strip_comments
from analyzer.models import Page, Status


class StubFetcher:
    def __init__(self, pages=None, limit=4):
        self.pages = pages or {}
        self.settings = SimpleNamespace(max_external_scripts=limit)
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = self.pages.get(url, FetchError("http_403"))
        if isinstance(result, Exception):
            raise result
        return result


@pytest.mark.parametrize(
    "source",
    [
        'document.addEventListener("keydown", e => { console.log(e.key); }); fetch("/health");',
        'document.addEventListener("input", e => { validate(e.target.value); });',
        "eval(function(p,a,c,k,e,d){return p;});",
        'const api = "https://api.telegram.org/bot";',
        '// addEventListener("input", e => { fetch("/log", {body:e.target.value}); });',
        '/* addEventListener("input", e => { fetch("/log", {body:e.target.value}); }); */',
        'document.addEventListener("keydown", e => { fetch("/metrics", {body:"focus"}); });',
    ],
)
def test_weak_signals_do_not_trigger_keylogger(source):
    assert analyze_script(source)[0] is False


@pytest.mark.parametrize(
    "source",
    [
        'document.addEventListener ( "input" , function(e) { fetch ( "/log", {body: e.target.value}); });',
        "field.addEventListener('keydown', (event) => {navigator.sendBeacon('/log', event.key);});",
        'field.onkeyup = function(e) { fetch("/log", {body:e.key}); };',
        "field.on('input', e => { $.post('/log', e.target.value); });",
    ],
)
def test_input_transmission_callback_is_suspicious(source):
    assert analyze_script(source)[0] is True


def test_comment_stripping_preserves_urls():
    assert "https://api.telegram.org/bot" in strip_comments(
        'const x="https://api.telegram.org/bot"; // comment'
    )


async def test_external_relative_script_and_base_are_scanned():
    page = Page(
        "https://shop.example/path/index",
        '<base href="/assets/"><script src="capture.js"></script>',
    )
    script_url = "https://shop.example/assets/capture.js"
    fetcher = StubFetcher(
        {
            script_url: Page(
                script_url, 'field.oninput = e => {fetch("/log", {body:e.target.value});};'
            )
        }
    )
    result = await check_keylogger(page, fetcher)
    assert result.status == Status.SUSPICIOUS
    assert fetcher.calls == [(script_url, {"kind": "script"})]


async def test_inline_handler_is_scanned():
    page = Page("https://shop.example", "<input oninput=\"fetch('/log', {body:this.value});\">")
    assert (await check_keylogger(page, StubFetcher())).status == Status.SUSPICIOUS


async def test_missing_external_script_is_inconclusive():
    page = Page("https://shop.example/", '<script src="/missing.js"></script>')
    assert (await check_keylogger(page, StubFetcher())).status == Status.INCONCLUSIVE


async def test_external_script_limit_is_reported():
    page = Page(
        "https://shop.example/", '<script src="/a.js"></script><script src="/b.js"></script>'
    )
    fetcher = StubFetcher(
        {"https://shop.example/a.js": Page("https://shop.example/a.js", 'console.log("ok");')},
        limit=1,
    )
    assert (await check_keylogger(page, fetcher)).status == Status.INCONCLUSIVE
    assert len(fetcher.calls) == 1


async def test_json_data_script_is_not_executed_code():
    page = Page(
        "https://shop.example/",
        '<script type="application/ld+json">{"api":"api.telegram.org/bot", "code":"fetch(value)"}</script>',
    )
    assert (await check_keylogger(page, StubFetcher())).warnings == ()


@pytest.mark.parametrize(
    "text,expected",
    [
        ("https://shop.ir/", True),
        ("www.shop.ir", True),
        ("fake-shop.ir", False),
        ("shop.ir.evil.test", False),
        ("myshop.ir", False),
    ],
)
def test_exact_seal_domain_boundary(text, expected):
    assert host_matches(text, "shop.ir") is expected


async def test_missing_seal_or_http_does_not_prove_phishing():
    page = Page("http://gov.example", "<h1>سامانه ثنا</h1>")
    result = await check_enamad(page, StubFetcher())
    assert result.status == Status.NOT_DETECTED
    assert len(result.warnings) == 2


async def test_seal_host_substring_spoof_is_rejected_without_fetch():
    page = Page(
        "https://shop.ir",
        '<a href="https://trustseal.enamad.ir.evil.test/"><img src="enamad.png"></a>',
    )
    fetcher = StubFetcher()
    assert (await check_enamad(page, fetcher)).status == Status.SUSPICIOUS
    assert not fetcher.calls


async def test_seal_request_is_direct_and_bound_to_official_host():
    seal_url = "https://trustseal.enamad.ir/?id=1"
    page = Page("https://shop.ir", f'<a href="{seal_url}"><img src="enamad.png"></a>')
    fetcher = StubFetcher({seal_url: Page(seal_url, "<p>دامنه: shop.ir</p>")})
    assert (await check_enamad(page, fetcher)).status == Status.NOT_DETECTED
    assert fetcher.calls == [(seal_url, {"allowed_host": "trustseal.enamad.ir"})]


async def test_network_failure_is_not_phishing():
    page = Page("https://shop.ir", '<a href="https://trustseal.enamad.ir/?id=1">seal</a>')
    assert (await check_enamad(page, StubFetcher())).status == Status.INCONCLUSIVE


async def test_explicit_seal_domain_mismatch():
    seal_url = "https://trustseal.enamad.ir/?id=1"
    page = Page("https://shop.ir", f'<a href="{seal_url}">seal</a>')
    fetcher = StubFetcher({seal_url: Page(seal_url, "دامنه: fake-shop.ir")})
    assert (await check_enamad(page, fetcher)).status == Status.SUSPICIOUS


async def test_captcha_or_dynamic_seal_is_inconclusive():
    seal_url = "https://trustseal.enamad.ir/?id=1"
    page = Page("https://shop.ir", f'<a href="{seal_url}">seal</a>')
    fetcher = StubFetcher({seal_url: Page(seal_url, "Please verify you are human")})
    assert (await check_enamad(page, fetcher)).status == Status.INCONCLUSIVE


@pytest.mark.parametrize(
    "source",
    [
        """const example = 'addEventListener("input", e => {fetch("/log", {body:e.target.value});});';""",
        """const endpoint="https://api.telegram.org/bot"; const data=field.value; fetch('/health');""",
        """field.oninput=e=>{console.log(e.target.value); const help="fetch('/log')";};""",
        """field.oninput=e=>{fetch('/health'); const help="e.target.value";};""",
    ],
)
def test_quoted_code_and_unrelated_telegram_signals_are_not_exfiltration(source):
    assert analyze_script(source)[0] is False


def test_constructing_xhr_without_sending_is_not_exfiltration():
    source = "field.oninput=e=>{const xhr = new XMLHttpRequest(); const value=e.target.value;};"
    assert analyze_script(source)[0] is False


def test_xhr_send_and_named_inline_function_are_scanned():
    source = 'field.addEventListener("input", function capture(e) { xhr.send(e.target.value); });'
    assert analyze_script(source)[0] is True
