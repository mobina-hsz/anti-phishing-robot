import asyncio
import re
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import CommandStart
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

# import the brains
from analyzer.enamad_checker import check_enamad
from analyzer.infrastructure_checker import check_infrastructure
from analyzer.keylogger_detector import check_keylogger

# TODO: move token to env or config file before production
TOKEN = "8986149133:AAHRhl7menehDfl5o1dWx70MUTQA1uQrNqA"

# regex for extracting raw links
link_pattern = re.compile(r'(?i)\b(?:https?://|www\.)[^\s()<>]+(?:[^\s`!()\[\]{};:\'".,<>?«»“”‘’]|\b)')

bot = Bot(token=TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

print("init bot...")

@dp.message(CommandStart())
async def start_cmd(message: types.Message):
    hello_msg = (
        "🛡 <b>به رادار فیشینگ ایرانی خوش آمدید!</b>\n\n"
        "پیامک‌های مشکوک (ثنا، سهام عدالت، رجیستری و...) را برای من فوروارد کنید "
        "یا لینک سایت را بفرستید تا در کسری از ثانیه آن را آنالیز کنم."
    )
    await message.answer(hello_msg)

@dp.message(F.text)
async def check_msg(message: types.Message):
    msg_txt = message.text
    urls = set(link_pattern.findall(msg_txt))
    
    if not urls:
        await message.reply("هیچ لینکی تو این پیام پیدا نکردم! مطمئنی لینک داره؟")
        return

    tmp_msg = await message.reply("⏳ در حال کالبدشکافی لینک و بررسی سورس‌کد...")

    for u in urls:
        if not u.startswith('http'):
            u = 'http://' + u
            
        print(f"found link: {u}")
        
        
        is_global_safe, infra_msg = await check_infrastructure(u)
        if is_global_safe:
            print(f"global safe -> {u}")
            await tmp_msg.edit_text(f"✅ <b>بررسی شد!</b>\n\nلینک: <code>{u}</code>\nوضعیت: <b>امن (سرویس بین‌المللی)</b>\nدلیل: {infra_msg}")
            continue

       
        is_phishing, phish_why = await check_enamad(u)
        
        
        is_keylogger, key_why = await check_keylogger(u)

        
        if is_phishing or is_keylogger:
            print(f"alert -> {u} (phish:{is_phishing}, keylog:{is_keylogger})")
            
            
            phish_status = "🔴 <b>قطعی</b>" if is_phishing else "🟢 امن"
            keylog_status = "🔴 <b>شناسایی شد</b>" if is_keylogger else "🟢 موردی یافت نشد"
            
            
            final_reason = ""
            if is_phishing:
                final_reason += f"🔸 <b>دلیل فیشینگ:</b> {phish_why}\n"
            if is_keylogger:
                final_reason += f"🔸 <b>دلیل بدافزار:</b> {key_why}\n"

            bad_msg = (
                f"🚨 <b>هشدار امنیتی شدید!</b> 🚨\n\n"
                f"لینک: <code>{u}</code>\n\n"
                f"وضعیت فیشینگ: {phish_status}\n"
                f"وضعیت کی‌لاگر: {keylog_status}\n\n"
                f"{final_reason}\n"
                f"<i>این لینک برای آموزش سیستم دفاعی ما ذخیره شد. ممنون از گزارشت!</i>"
            )
            await tmp_msg.edit_text(bad_msg)
            
        else:
            print(f"safe -> {u}")
            ok_msg = (
                f"✅ <b>بررسی شد!</b>\n\n"
                f"لینک: <code>{u}</code>\n"
                f"وضعیت فیشینگ: <code>امن</code>\n"
                f"وضعیت کی‌لاگر: <code>امن</code>\n\n"
                f"دلیل: {phish_why}"
            )
            await tmp_msg.edit_text(ok_msg)

async def main():
    print("polling...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nexit")