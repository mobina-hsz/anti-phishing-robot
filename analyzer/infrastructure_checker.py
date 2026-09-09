import urllib.parse
import aiohttp

async def check_infrastructure(url):

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    
    
    global_giants = ['netflix.com', 'linkedin.com', 'google.com', 'youtube.com', 'github.com', 'microsoft.com', 'apple.com']
    if any(domain == g or domain.endswith('.' + g) for g in global_giants):
        return True, "این سایت یک سرویس بین‌المللی معتبر و شناخته‌شده است."

    heads = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url, headers=heads, allow_redirects=True, timeout=5) as res:
                headers = res.headers
                
                
                server = headers.get('Server', '').lower()
                is_cloudflare = 'cloudflare' in server or 'cf-ray' in headers
                
                
                if is_cloudflare:
                    
                    pass
                    
                return False, f"زیرساخت بررسی شد. (Cloudflare: {is_cloudflare})"
    except Exception:
        return False, "مشکل در استعلام هدرهای زیرساختی."