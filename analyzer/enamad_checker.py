import urllib.parse
import aiohttp
import asyncio
import ssl
import re
import ipaddress
from bs4 import BeautifulSoup

def is_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:

        return False
#برای اینکه هربار با صدا کردن تابع ساخته نشه
target_keywords = ['sana', 'eadl', 'sahamedalat', 'shaparak', 'enamad', 'maliyat']

async def check_enamad(url):

    parsed_url = urllib.parse.urlparse(url)
    current_domain = parsed_url.netloc.lower()

#_________________________________step 1
#checking if is it an ip
    flag = is_ip(current_domain)
    if(flag):
        return True, "استفاده از آدرس IP مستقیم به جای نام دامنه (رفتار به شدت مشکوک کلاهبرداران)"

#_________________________________step 2
#checking how many parts does its domain have
    domain_parts = current_domain.split('.')
    max_normal_domain_parts = 3
    if len(domain_parts) > max_normal_domain_parts:
        if any(kw in current_domain for kw in target_keywords):
            return True, "جعل نام سامانه‌های دولتی در ساب‌دامینِ یک سایت نامعتبر"
        return True, f"استفاده از ساب‌دامین‌های تو در تو و غیرعادی ({len(domain_parts)} بخش)"

#__________________________________step 3

    heads = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    ssl_exists = await has_ssl(current_domain)
    if not ssl_exists:
        return True, "سایت فاقد گواهی SSL است (نشانه ضعیف اما قابل توجه از نامعتبر بودن سایت)."

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=heads, ssl=ctx, timeout=7, allow_redirects=True) as res:
                
                if res.status != 200:
                    return True, f"سرور سایت خطای {res.status} داد."
                
                html = await res.text()
                soup = BeautifulSoup(html, 'html.parser')
                page_text = soup.get_text()

                
                persian_chars_pattern = re.compile(r'[\u0600-\u06FF]')
                has_persian = bool(persian_chars_pattern.search(page_text))

                if not has_persian and not current_domain.endswith('.ir'):
                    return False, "این یک وب‌سایت بین‌المللی است و محتوای مرتبط با فیشینگ داخلی ندارد."

                
                target_words_fa = ['درگاه پرداخت', 'سامانه ثنا', 'سهام عدالت', 'ابلاغیه الکترونیکی قضایی', 'شاپرک', 'یارانه']
                page_text_lower = page_text.lower()
                is_sensitive_page = any(w in page_text_lower for w in target_words_fa)

                enamad_imgs = soup.find_all('img', src=re.compile(r'enamad', re.I))
                enamad_links = soup.find_all('a', href=re.compile(r'enamad', re.I))
                
                if is_sensitive_page and not enamad_imgs and not enamad_links:
                    return True, "صفحه حساس است اما هیچ نماد اعتمادی ندارد."

                if enamad_imgs and not enamad_links:
                    return True, "لوگوی اینماد به صورت عکسِ نمایشی و جعلی قرار داده شده است."

                if not enamad_links:
                    return False, "سایت فارسی است اما نشانه خاصی از درگاه یا اینماد در آن پیدا نشد."

                
                enamad_verified = False
                
                for a in enamad_links:
                    enamad_href = a.get('href', '')
                    
                    if 'trustseal.enamad.ir' not in enamad_href.lower():
                        return True, "لینک اینماد به آدرس نامعتبر هدایت می‌شود."
                    
                    try:
                        async with session.get(enamad_href, headers=heads, ssl=ctx, timeout=7) as enamad_res:
                            if enamad_res.status == 200:
                                enamad_html = await enamad_res.text()
                                enamad_soup = BeautifulSoup(enamad_html, 'html.parser')
                                enamad_page_text = enamad_soup.get_text().lower()
                                
                                clean_current_domain = current_domain.replace('www.', '')
                                
                                if clean_current_domain in enamad_page_text:
                                    enamad_verified = True
                                    break  
                                else:
                                    return True, f"جعل اینماد! مجوز موجود متعلق به دامنه دیگری است و ربطی به {clean_current_domain} ندارد."
                            else:
                                return True, f"سرور مرجع اینماد پاسخ نداد (خطای {enamad_res.status}). اعتبار سایت قابل تایید نیست."
                    except Exception as e:
                       
                        return True, f"ارتباط با سرور اینماد برای بررسی دامنه قطع شد ({type(e).__name__}). بنابراین اعتبار سایت رد می‌شود."
                
                if enamad_links and not enamad_verified:
                    return True, "لینک اینماد در سایت وجود دارد اما توسط سرور رسمی تایید نشد."

                return False, "وضعیت اینماد، تطبیق دامنه و پاسخگویی سرور نرمال و کاملاً معتبر است."

    except asyncio.TimeoutError:
        return True, "پاسخی از سرور دریافت نشد (Timeout)."
        
    except Exception as e:
        return True, f"خطای شبکه در دسترسی به سایت. دلیل: {type(e).__name__}"