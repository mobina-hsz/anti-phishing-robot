import urllib.parse
import aiohttp
import asyncio
import ssl
import re
from bs4 import BeautifulSoup

async def check_enamad(url):

    parsed_url = urllib.parse.urlparse(url)
    current_domain = parsed_url.netloc.lower()
    

    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$")
    if ip_pattern.match(current_domain):
        return True, "استفاده از آدرس IP مستقیم به جای نام دامنه (رفتار به شدت مشکوک کلاهبرداران)"

    domain_parts = current_domain.split('.')
    if len(domain_parts) > 3:
        target_keywords = ['sana', 'eadl', 'sahamedalat', 'shaparak', 'enamad', 'maliyat']
        if any(kw in current_domain for kw in target_keywords):
            return True, "جعل نام سامانه‌های دولتی در ساب‌دامینِ یک سایت نامعتبر"
        return True, f"استفاده از ساب‌دامین‌های تو در تو و غیرعادی ({len(domain_parts)} بخش)"

    heads = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        async with aiohttp.ClientSession() as session:
        
            async with session.get(url, headers=heads, ssl=ctx, timeout=7, allow_redirects=True) as res:
                
                if res.status != 200:
                    return True, f"سرور سایت به جای محتوا، کد خطای HTTP {res.status} را برگرداند (احتمالاً سایت مسدود شده است)."
                
                html = await res.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                page_text = soup.get_text()

                
               
                persian_chars_pattern = re.compile(r'[\u0600-\u06FF]')
                has_persian = bool(persian_chars_pattern.search(page_text))

               
                if not has_persian and not current_domain.endswith('.ir'):
                    return False, "این یک وب‌سایت بین‌المللی/خارجی است و محتوای بومی یا مرتبط با فیشینگ داخلی ندارد."

                
                target_words_fa = ['درگاه پرداخت', 'سامانه ثنا', 'سهام عدالت', 'ابلاغیه الکترونیکی قضایی', 'شاپرک', 'یارانه']
                page_text_lower = page_text.lower()
                is_sensitive_page = any(w in page_text_lower for w in target_words_fa)

                enamad_imgs = soup.find_all('img', src=re.compile(r'enamad', re.I))
                enamad_links = soup.find_all('a', href=re.compile(r'enamad', re.I))
                
                if is_sensitive_page and not enamad_imgs and not enamad_links:
                    return True, "صفحه دارای محتوای بانکی/قضایی است اما هیچ نماد اعتمادی در آن یافت نشد."

                if enamad_imgs and not enamad_links:
                    return True, "لوگوی اینماد به صورت عکسِ نمایشی و بدون لینک قرار داده شده است (جعل قطعی)."

                if is_sensitive_page and not enamad_links:
                    return True, "هیچ لینک معتبری برای نماد اعتماد در صفحه حساس یافت نشد."
                
                
                if not enamad_links:
                    return False, "سایت فارسی است اما نشانه خاصی از درگاه یا اینماد در آن پیدا نشد (بررسی ظاهری نرمال)."

                
                for a in enamad_links:
                    enamad_href = a.get('href', '')
                    
                    if 'trustseal.enamad.ir' not in enamad_href.lower():
                        return True, "لینک اینماد نامعتبر است و به جای سرور رسمی، به منابع متفرقه هدایت می‌شود."
                    
                    try:
                        async with session.get(enamad_href, headers=heads, ssl=ctx, timeout=5) as enamad_res:
                            if enamad_res.status == 200:
                                enamad_html = await enamad_res.text()
                                enamad_soup = BeautifulSoup(enamad_html, 'html.parser')
                                enamad_page_text = enamad_soup.get_text().lower()
                                
                                clean_current_domain = current_domain.replace('www.', '')
                                
                                if clean_current_domain not in enamad_page_text:
                                    return True, f"جعل خطرناک اینماد! لوگوی اینماد به صفحه رسمی وصل است، امّا بررسی‌ها نشان داد این مجوز متعلق به دامنه دیگری است و ربطی به {clean_current_domain} ندارد."
                    except Exception:
                        pass
                
                return False, "وضعیت اینماد، تطبیق دامنه و پاسخگویی سرور نرمال و معتبر است."

    except asyncio.TimeoutError:
        return True, "پاسخی از سرور دریافت نشد (Timeout). معمولاً سایت‌های فیشینگ به سرعت توسط هاستینگ خاموش می‌شوند."
        
    except Exception as e:
        err_msg = type(e).__name__
        return True, f"خطای شبکه در دسترسی به سایت. دلیل فنی: {err_msg}"