"""Telegram interface, bounded scan admission, and private admin monitoring."""

import asyncio
import logging
import re
import time
from collections import OrderedDict
from html import escape
from logging.handlers import RotatingFileHandler

from aiogram import Bot, Dispatcher, F, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatType, ParseMode
from aiogram.filters import Command, CommandStart

from analyzer.http_client import FetchError, normalize_url
from analyzer.models import ScanResult, Status
from analyzer.scanner import scan_url
from config import ROOT, Settings
from monitoring import Monitor

logger = logging.getLogger(__name__)
LINK_PATTERN = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\"'«»]+")
STATUS_FA = {
    Status.SUSPICIOUS: "🔴 نشانهٔ مشکوک",
    Status.NOT_DETECTED: "🟢 موردی یافت نشد",
    Status.INCONCLUSIVE: "🟡 بررسی نامشخص",
}


def extract_urls(message: types.Message) -> list[str]:
    """Include text links and respect Telegram's UTF-16 entity offsets."""
    text = message.text or message.caption or ""
    urls = []
    for entity in message.entities or message.caption_entities or []:
        if entity.type == "text_link" and entity.url:
            urls.append(entity.url)
        elif entity.type == "url":
            encoded = text.encode("utf-16-le")
            urls.append(
                encoded[entity.offset * 2 : (entity.offset + entity.length) * 2].decode("utf-16-le")
            )
    urls.extend(match.group(0).rstrip(".,;!?،؛؟)]}…") for match in LINK_PATTERN.finditer(text))
    # A bare domain is accepted only when the entire message is a single URL-like value.
    candidate = text.strip()
    if not urls and re.fullmatch(r"(?:[\w-]+\.)+[\w-]{2,}(?::\d+)?(?:/[^\s]*)?", candidate):
        urls.append(candidate)
    result = []
    for value in urls:
        try:
            value = normalize_url(value)
        except FetchError:
            # Keep invalid submitted URLs for an explicit inconclusive result; never fetch them.
            pass
        if value not in result:
            result.append(value)
    return result


def render_result(result: ScanResult) -> str:
    heading = {
        Status.SUSPICIOUS: "🚨 <b>نشانهٔ مشکوک دیده شد</b>",
        Status.NOT_DETECTED: "✅ <b>بررسی انجام شد</b>",
        Status.INCONCLUSIVE: "🟡 <b>بررسی کامل نشد</b>",
    }[result.status]
    blocks = [heading, f"لینک: <code>{escape(result.url[:750])}</code>"]
    for title, check in (
        ("فیشینگ / اینماد", result.phishing),
        ("خروج اطلاعات / کی‌لاگر", result.keylogger),
    ):
        blocks.append(f"<b>{title}:</b> {STATUS_FA[check.status]}\n{escape(check.reason[:450])}")
    warnings = list(dict.fromkeys(result.phishing.warnings + result.keylogger.warnings))
    if warnings:
        blocks.append(
            "<b>نکات:</b>\n" + "\n".join("• " + escape(item[:250]) for item in warnings[:4])
        )
    if result.errors:
        blocks.append("کد خطا: <code>" + escape(", ".join(result.errors)[:180]) + "</code>")
    blocks.append(
        f"⏱ {result.elapsed_ms / 1000:.1f} ثانیه\n<i>این بررسی ایستا است؛ نبود نشانه، تضمین امنیت نیست.</i>"
    )
    return "\n\n".join(blocks)


class ScanGate:
    """Reject excess work immediately instead of building an unbounded queue."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.active = 0
        self.users: set[int] = set()
        self.last_seen: OrderedDict[int, float] = OrderedDict()
        self.rejected = 0

    def admit(self, user_id: int) -> bool:
        now = time.monotonic()
        if (
            self.active >= self.settings.max_concurrent_scans
            or user_id in self.users
            or now - self.last_seen.get(user_id, -float("inf"))
            < self.settings.user_cooldown_seconds
        ):
            self.rejected += 1
            return False
        self.last_seen[user_id] = now
        self.last_seen.move_to_end(user_id)
        while len(self.last_seen) > 10000:
            self.last_seen.popitem(last=False)
        self.active += 1
        self.users.add(user_id)
        return True

    def release(self, user_id: int):
        self.active -= 1
        self.users.discard(user_id)


def is_admin(message: types.Message, settings: Settings) -> bool:
    return bool(
        message.from_user
        and message.from_user.id in settings.admin_ids
        and message.chat.type == ChatType.PRIVATE
    )


def build_dispatcher(settings: Settings, monitor: Monitor) -> Dispatcher:
    dp = Dispatcher()
    gate = ScanGate(settings)
    started = time.monotonic()

    @dp.message(CommandStart())
    async def start_cmd(message: types.Message):
        await message.answer(
            "🛡 <b>رادار فیشینگ ایرانی</b>\n\n"
            "پیام مشکوک را فوروارد کن یا لینک سایت را بفرست. "
            "صفحه و بخشی از جاوااسکریپت آن برای نشانه‌های جعل اینماد و خروج اطلاعات بررسی می‌شوند.\n\n"
            "نبود نشانهٔ مشکوک به معنی امنیت قطعی نیست. راهنما: /help"
        )

    @dp.message(Command("help"))
    async def help_cmd(message: types.Message):
        text = (
            "<b>راهنما</b>\nلینک کامل، دامنهٔ تنها، پیام فورواردشده یا لینک داخل توضیح عکس را بفرست.\n"
            f"در هر پیام حداکثر {settings.max_urls_per_message} لینک بررسی می‌شود.\n"
            "🔴 نشانهٔ مشکوک: نیازمند بررسی دستی\n🟢 موردی یافت نشد: تضمین امنیت نیست\n"
            "🟡 نامشخص: دریافت یا بررسی کامل نشده است\n\nشناسه عددی خودت: /myid"
        )
        if is_admin(message, settings):
            text += "\n\nدستورهای مدیر: /status /recent /errors"
        await message.answer(text)

    @dp.message(Command("myid"))
    async def myid_cmd(message: types.Message):
        if message.from_user and message.chat.type == ChatType.PRIVATE:
            await message.answer(f"شناسه عددی شما: <code>{message.from_user.id}</code>")

    @dp.message(Command("status", "recent", "errors"))
    async def admin_cmd(message: types.Message):
        if not is_admin(message, settings):
            await message.answer("این دستور فقط برای مدیر و در گفت‌وگوی خصوصی فعال است.")
            return
        command = (message.text or "").split()[0].split("@", 1)[0]
        if command == "/status":
            values = monitor.summary()
            await message.answer(
                "📊 <b>وضعیت رادار</b>\n"
                f"زمان اجرای این پردازش: {int(time.monotonic() - started)} ثانیه\n"
                f"بررسی فعال: {gate.active}/{settings.max_concurrent_scans}\n"
                f"درخواست ردشده به دلیل محدودیت (این اجرا): {gate.rejected}\n\n"
                f"کل بررسی‌های ثبت‌شده: {values['total']}\n"
                f"مشکوک: {values['suspicious']}\n"
                f"بدون نشانه: {values['not_detected']}\n"
                f"نامشخص: {values['inconclusive']}\n"
                f"بررسی دارای خطا: {values['errors']}\n"
                f"میانگین زمان: {values['average_ms']} ms\n"
                f"ردیف‌های تاریخچه: {values['retained']} / 10000"
            )
        else:
            rows = monitor.recent(errors_only=command == "/errors")
            if not rows:
                await message.answer("هنوز رکوردی برای نمایش وجود ندارد.")
                return
            title = "⚠️ خطاهای اخیر" if command == "/errors" else "🕒 بررسی‌های اخیر"
            lines = [f"<b>{title}</b> (زمان UTC)"]
            for row in rows:
                lines.append(
                    f"<code>{row['created_at']}</code>\n"
                    f"<code>{escape(row['host'][:150])}</code> — {STATUS_FA[Status(row['status'])]}\n"
                    f"{row['elapsed_ms']} ms · <code>{escape(row['errors'][:100]) or '—'}</code>"
                )
            await message.answer("\n\n".join(lines))

    @dp.message(F.text | F.caption)
    async def check_msg(message: types.Message):
        if (message.text or "").startswith("/"):
            return
        urls = extract_urls(message)
        if not urls:
            await message.reply("لینکی پیدا نکردم؛ آدرس کامل سایت یا دامنه را بفرست.")
            return
        if not message.from_user:
            return
        user_id = message.from_user.id
        if not gate.admit(user_id):
            await message.reply(
                "⏳ رادار مشغول است یا درخواست قبلی تو هنوز تمام نشده؛ کمی بعد دوباره تلاش کن."
            )
            return
        try:
            if len(urls) > settings.max_urls_per_message:
                await message.reply(
                    f"فقط {settings.max_urls_per_message} لینک اول این پیام بررسی می‌شوند."
                )
            for url in urls[: settings.max_urls_per_message]:
                pending = await message.reply("⏳ در حال بررسی مستقیم صفحه و جاوااسکریپت...")
                result = await scan_url(url, settings)
                try:
                    monitor.record(result)
                except Exception as exc:
                    logger.error("Monitoring write failed: %s", type(exc).__name__)
                await pending.edit_text(render_result(result))
        finally:
            gate.release(user_id)

    @dp.error()
    async def handle_error(event: types.ErrorEvent):
        logger.error("Telegram update failed: %s", type(event.exception).__name__)
        return True

    return dp


def configure_logging(settings: Settings):
    log_dir = ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            RotatingFileHandler(
                log_dir / "bot.log", maxBytes=1048576, backupCount=3, encoding="utf-8"
            ),
        ],
        force=True,
    )
    # Framework exceptions may include complete request URLs; keep application logs sanitized.
    logging.getLogger("aiogram").setLevel(logging.CRITICAL)
    logging.getLogger("aiohttp").setLevel(logging.CRITICAL)


async def main():
    settings = Settings.from_env()
    configure_logging(settings)
    monitor = Monitor(settings.monitor_db)
    bot = None
    try:
        bot = Bot(
            token=settings.token,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML, link_preview_is_disabled=True),
        )
        dp = build_dispatcher(settings, monitor)
        logger.info(
            "Bot initialized; admin_count=%s scan_limit=%s",
            len(settings.admin_ids),
            settings.max_concurrent_scans,
        )
        await dp.start_polling(
            bot, tasks_concurrency_limit=20, allowed_updates=["message"], close_bot_session=False
        )
    finally:
        if bot:
            await bot.session.close()
        monitor.close()
        logger.info("Bot stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    except Exception as exc:
        logging.getLogger(__name__).error("Startup failed: %s", type(exc).__name__)
        if isinstance(exc, ValueError) and not str(exc).startswith("Token"):
            logging.getLogger(__name__).error("Check BOT_TOKEN and settings in .env")
        raise SystemExit(1) from None
