from unittest.mock import AsyncMock

import pytest
from aiogram import Bot, types
from aiogram.client.session.base import BaseSession
from aiogram.methods import EditMessageText, SendMessage

import main_bot
from analyzer.models import CheckResult, ScanResult, Status
from config import Settings
from monitoring import Monitor


class TelegramStub(BaseSession):
    def __init__(self):
        super().__init__()
        self.calls = []

    async def close(self):
        pass

    async def make_request(self, bot, method, timeout=None):
        self.calls.append(method)
        assert isinstance(method, (SendMessage, EditMessageText))
        return types.Message(
            message_id=len(self.calls),
            date=0,
            chat={"id": method.chat_id, "type": "private"},
            text=method.text,
        ).as_(bot)

    async def stream_content(self, *args, **kwargs):
        yield b""


def update(text, user_id=42, chat_type="private"):
    return types.Update(
        update_id=1,
        message=types.Message(
            message_id=10,
            date=0,
            chat={"id": user_id, "type": chat_type},
            text=text,
            from_user={"id": user_id, "is_bot": False, "first_name": "User"},
        ),
    )


async def test_two_links_produce_two_separate_results(monkeypatch, tmp_path):
    clean = CheckResult(Status.NOT_DETECTED, "موردی یافت نشد")
    checker = AsyncMock(
        side_effect=[
            ScanResult("https://one.example/", clean, clean, 12),
            ScanResult("https://two.example/", clean, clean, 14),
        ]
    )
    monkeypatch.setattr(main_bot, "scan_url", checker)
    monitor = Monitor(tmp_path / "monitor.db")
    session = TelegramStub()
    bot = Bot("123456:TEST_ONLY_NOT_A_REAL_CREDENTIAL", session=session)
    dp = main_bot.build_dispatcher(Settings(), monitor)
    try:
        await dp.feed_update(bot, update("https://one.example/ https://two.example/"))
        edits = [method for method in session.calls if isinstance(method, EditMessageText)]
        assert len(edits) == 2
        assert edits[0].message_id != edits[1].message_id
        assert "one.example" in edits[0].text
        assert "two.example" in edits[1].text
        assert monitor.summary()["total"] == 2
    finally:
        monitor.close()
        await bot.session.close()


@pytest.mark.parametrize(
    "user_id,chat_type,authorized",
    [(42, "private", True), (43, "private", False), (42, "group", False)],
)
async def test_monitor_command_permissions(tmp_path, user_id, chat_type, authorized):
    monitor = Monitor(tmp_path / "monitor.db")
    session = TelegramStub()
    bot = Bot("123456:TEST_ONLY_NOT_A_REAL_CREDENTIAL", session=session)
    dp = main_bot.build_dispatcher(Settings(admin_ids=frozenset({42})), monitor)
    try:
        await dp.feed_update(bot, update("/status", user_id, chat_type))
        assert ("کل بررسی‌های ثبت‌شده" in session.calls[-1].text) is authorized
    finally:
        monitor.close()
        await bot.session.close()
