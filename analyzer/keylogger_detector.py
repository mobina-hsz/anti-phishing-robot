import aiohttp
import ssl
import re
from bs4 import BeautifulSoup

async def check_keylogger(url):
    """
    تحلیلگر استاتیک بدافزار (سه لایه):
    ۱. شکار توکن‌های ربات تلگرام
    ۲. تشخیص الگوی رفتاری «شنود کیبورد + ارسال شبکه»
    ۳. شناسایی کدهای رمزنگاری‌شده و مبهم (Obfuscation)
    """
    heads = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=heads, ssl=ctx, timeout=7) as res:
                if res.status != 200:
                    return False, "سایت در دسترس نیست."
                
                html = await res.text()

                tg_pattern = re.compile(r'api\.telegram\.org/bot(\d+:[a-zA-Z0-9_-]{35,})', re.I)
                matches = tg_pattern.findall(html)
                
                if matches:
                    token = matches[0]
                    masked_token = token[:10] + "..." + token[-5:]
                    return True, f"ارسال اطلاعات به ربات تلگرام! 🦠 (توکن هکر: {masked_token})"

                soup = BeautifulSoup(html, 'html.parser')
                scripts = soup.find_all('script')

                for script in scripts:
                    script_text = script.string
                    if not script_text:
                        continue
                    
                    script_text_lower = script_text.lower()


                    listen_patterns = ['keyup', 'keydown', 'keypress', 'addeventlistener("input"', "addeventlistener('input'"]
                    
                    exfil_patterns = ['fetch(', 'xmlhttprequest', 'navigator.sendbeacon', '$.ajax', '$.post']
                    
                    has_listen = any(p in script_text_lower for p in listen_patterns)
                    has_exfil = any(p in script_text_lower for p in exfil_patterns)
                    
                    if has_listen and has_exfil:
                        return True, "الگوی کی‌لاگر تحت وب! کدهای این صفحه همزمان در حال ضبط کلیدهای فشرده‌شده و ارسال آن‌ها به یک سرور نامشخص هستند. 🦠"


                    if 'eval(function(p,a,c,k,e,d)' in script_text_lower or 'eval(function(p,a,c,k,e,r)' in script_text_lower:
                        return True, "کدهای مخفی (Obfuscated) یافت شد! از تابع Packer برای مخفی‌سازی یک بدافزار یا کی‌لاگر در این صفحه استفاده شده است. 🦠"
                    
                    
                    hex_pattern = re.compile(r'\\x[0-9a-fA-F]{2}')
                    hex_count = len(hex_pattern.findall(script_text))
                    
                    obfuscated_vars = len(re.findall(r'_0x[0-9a-fA-F]+', script_text))

                    
                    if hex_count > 20 or obfuscated_vars > 10:
                        return True, "تراکم غیرعادی کدهای مبهم (Hex/Obfuscation) در جاوااسکریپت سایت کشف شد که نشان‌دهنده تلاش برای فرار از آنتی‌ویروس‌هاست. 🦠"

                return False, "موردی یافت نشد."

    except Exception as e:
        print(f"keylogger err -> {type(e).__name__}")
        return False, "خطا در بررسی سورس برای کی‌لاگر."