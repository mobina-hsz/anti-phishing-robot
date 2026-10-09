from unittest.mock import AsyncMock

from aiogram import types

import analyzer.scanner as scanner
from analyzer.models import CheckResult, Page, ScanResult, Status
from config import Settings
from main_bot import ScanGate, extract_urls, is_admin, render_result
from monitoring import Monitor


def message(text="", **kwargs):
    return types.Message(
        message_id=1,
        date=0,
        chat={"id": 42, "type": "private"},
        from_user={"id": 42, "is_bot": False, "first_name": "User"},
        text=text,
        **kwargs,
    )


def test_urls_keep_order_and_do_not_swallow_punctuation():
    urls = extract_urls(
        message("https://one.example/a، https://two.example/?x=1&y=2 https://one.example/a")
    )
    assert urls == ["https://one.example/a", "https://two.example/?x=1&y=2"]


def test_hidden_link_and_utf16_entity():
    msg = message(
        "😀 لینک",
        entities=[
            types.MessageEntity(type="text_link", offset=3, length=4, url="https://one.example/")
        ],
    )
    assert extract_urls(msg) == ["https://one.example/"]
    text = "😀 https://one.example/a"
    msg = message(
        text,
        entities=[types.MessageEntity(type="url", offset=3, length=len("https://one.example/a"))],
    )
    assert extract_urls(msg) == ["https://one.example/a"]


def test_bare_domain():
    assert extract_urls(message("shop.example")) == ["https://shop.example/"]


def test_gate_enforces_busy_user_capacity_and_cooldown():
    gate = ScanGate(Settings(max_concurrent_scans=1))
    assert gate.admit(42)
    assert not gate.admit(42)
    assert not gate.admit(43)
    gate.release(42)
    assert not gate.admit(42)
    assert gate.admit(43)
    gate.release(43)
    assert gate.active == 0


def test_admin_must_have_id_and_private_chat():
    settings = Settings(admin_ids=frozenset({42}))
    assert is_admin(message(), settings)
    group = message().model_copy(update={"chat": types.Chat(id=-1, type="group")})
    assert not is_admin(group, settings)
    assert not is_admin(message(), Settings())


def make_result(url="https://shop.example/?password=secret", status=Status.NOT_DETECTED, errors=()):
    check = CheckResult(status, "Test <script> & evidence")
    return ScanResult(url, check, check, 1200, errors)


def test_html_is_escaped_and_no_absolute_safety_claim():
    rendered = render_result(make_result("https://shop.example/?a=1&b=<b>"))
    assert "&lt;script&gt;" in rendered
    assert "&amp;b=&lt;b&gt;" in rendered
    assert "تضمین امنیت نیست" in rendered


def test_suspicious_evidence_wins_over_partial_scan():
    result = ScanResult(
        "https://shop.example",
        CheckResult(Status.INCONCLUSIVE, "unknown"),
        CheckResult(Status.SUSPICIOUS, "signal"),
        1,
    )
    assert result.status == Status.SUSPICIOUS


def test_monitor_retains_counters_without_query_secrets(tmp_path):
    path = tmp_path / "monitor.sqlite3"
    monitor = Monitor(path)
    monitor.record(make_result(errors=("timeout",)))
    assert monitor.summary()["total"] == 1
    assert monitor.recent()[0]["host"] == "shop.example"
    assert "secret" not in str(monitor.recent())
    assert monitor.recent(errors_only=True)[0]["errors"] == "timeout"
    monitor.close()
    reopened = Monitor(path)
    assert reopened.summary()["total"] == 1
    reopened.close()


async def test_scanner_fetches_page_once_and_reuses_it(monkeypatch):
    page = Page("https://shop.example/", "<h1>Shop</h1>")
    getter = AsyncMock(return_value=page)
    monkeypatch.setattr(scanner.Fetcher, "get", getter)
    result = await scanner.scan_url("https://shop.example/", Settings())
    assert result.status == Status.NOT_DETECTED
    getter.assert_awaited_once_with("https://shop.example/")


async def test_failed_main_page_is_inconclusive_not_safe_or_phishing(monkeypatch):
    from analyzer.http_client import FetchError

    monkeypatch.setattr(scanner.Fetcher, "get", AsyncMock(side_effect=FetchError("http_403")))
    result = await scanner.scan_url("https://shop.example", Settings())
    assert result.status == Status.INCONCLUSIVE
    assert result.errors == ("http_403",)


async def test_internal_url_is_not_requested(monkeypatch):
    getter = AsyncMock()
    monkeypatch.setattr(scanner.Fetcher, "get", getter)
    result = await scanner.scan_url("http://127.0.0.1", Settings())
    assert result.status == Status.INCONCLUSIVE
    getter.assert_not_awaited()
