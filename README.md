<div align="center">

![Iran Phishing Radar](docs/banner.svg)

# 🛡 Iran Phishing Radar | رادار فیشینگ ایرانی

**A lightweight Telegram bot for suspicious link analysis**  
**بات سبک تلگرام برای بررسی نشانه‌های مشکوک در لینک‌ها**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![aiogram](https://img.shields.io/badge/aiogram-3.31-229ED9?logo=telegram&logoColor=white)
![HTTP](https://img.shields.io/badge/HTTP-Direct-2ee6bc)
![Monitoring](https://img.shields.io/badge/Monitoring-SQLite-003B57?logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-blue)

[فارسی](#فارسی) · [English](#english) · [Debug report](docs/DEBUG_REPORT.md) · [Future dataset](docs/DATASET_IDEA.md)

</div>

---

## فارسی

### ✨ این بات چه می‌کند؟

لینک یا پیام مشکوک را برای بات بفرست. بات **مستقیماً از سرور خودت** صفحه را دریافت می‌کند، پیوندهای اینماد و بخشی از جاوااسکریپت را بررسی می‌کند و نتیجه‌ای خوانا می‌فرستد. هیچ Cloudflare Worker، واسط دریافت صفحه، مرورگر خودکار یا مدل یادگیری ماشین لازم نیست.

| قابلیت | رفتار |
|---|---|
| دریافت مستقیم | صفحه اصلی فقط یک‌بار دریافت و بین تحلیلگرها استفاده می‌شود |
| بررسی اینماد | کنترل دقیق میزبان رسمی و تطبیق مرزی دامنه در محتوای مرجع |
| نشانه‌های خروج اطلاعات | خواندن مقدار ورودی همراه ارسال شبکه در همان callback ورودی/کیبورد |
| جاوااسکریپت خارجی | حداکثر ۴ فایل متمایز در هر صفحه؛ مسیر نسبی و `base` پشتیبانی می‌شوند |
| نتیجه شفاف | «مشکوک»، «موردی یافت نشد» یا «بررسی نامشخص» |
| مانیتورینگ سبک | دستورهای مدیر، تاریخچه SQLite و لاگ چرخشی انگلیسی |
| محدودیت منابع | زمان، حجم پاسخ، تعداد لینک، هم‌زمانی و فاصله درخواست هر کاربر |

> **مرز نتیجه:** این ابزار تحلیلگر ایستا و مبتنی بر قواعد است. نشانهٔ مشکوک، اثبات قطعی جرم یا کی‌لاگر نیست؛ نبود نشانه نیز تضمین امنیت نیست. خطای شبکه، گواهی نامعتبر، 403 و نبود اینماد به‌تنهایی برچسب فیشینگ ایجاد نمی‌کنند.

### 🚀 نصب و اجرا

پیش‌نیاز: **Python 3.11 یا جدیدتر**؛ این نسخه با Python 3.12 بررسی شده است. روی لینوکس ممکن است بستهٔ `python3-venv` هم لازم باشد.

از نسخهٔ اصلاح‌شدهٔ این پروژه استفاده کن. فایل‌های ZIP را استخراج کن و وارد پوشه‌ای شو که `main_bot.py` در آن است. سپس یکی از مسیرهای زیر را اجرا کن.

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

**Windows — CMD**

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
copy .env.example .env
```

**Windows — PowerShell**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

اگر PowerShell فعال‌سازی را مسدود کرد، با CMD کار کن یا مستقیماً `.\.venv\Scripts\python.exe` را به جای `python` اجرا کن؛ فعال‌سازی برای اجرای محیط مجازی اجباری نیست.

فایل `.env` را ویرایش کن:

```dotenv
BOT_TOKEN=YOUR_NEW_BOT_TOKEN
ADMIN_IDS=YOUR_NUMERIC_TELEGRAM_USER_ID
```

سپس اجرا:

```bash
python main_bot.py
```

`python main.py` هم همان بات را اجرا می‌کند. توکن یا شبکهٔ تلگرام نامعتبر باشد، اتصال واقعی برقرار نمی‌شود؛ فقط یک نمونه از بات را با همین توکن اجرا کن. اگر قبلاً webhook تنظیم کرده‌ای، قبل از استفاده از polling آن را از تنظیمات/API تلگرام حذف کن.

> **توکن قبلی را تعویض کن:** در نسخهٔ اصلی رپو، توکن بات به‌صورت عمومی قرار گرفته بود. از BotFather آن را revoke کن و توکن جدید بگیر. حذف از فایل فعلی، توکن قبلی را از تاریخچهٔ Git پاک نمی‌کند. در این نسخه توکن واقعی وجود ندارد و `.env` وارد Git نمی‌شود.

### 📊 پنل مدیر داخل تلگرام

داشبورد وب یا سرویس اضافی لازم نیست. در گفت‌وگوی خصوصی با بات:

| دستور | کاربرد |
|---|---|
| `/start` | معرفی بات |
| `/help` | راهنمای ارسال لینک و معنی نتیجه‌ها |
| `/myid` | نمایش شناسهٔ عددی خودت برای تنظیم `ADMIN_IDS` |
| `/status` | زمان اجرای پردازش، تعداد کارهای فعال، شمارنده‌ها و میانگین زمان |
| `/recent` | ۱۰ بررسی اخیر با دامنه، زمان، وضعیت و مدت بررسی |
| `/errors` | ۱۰ بررسی اخیر دارای خطای دریافت/تحلیل |

برای دریافت شناسه، بات را با `ADMIN_IDS=` خالی اجرا کن، `/myid` را بفرست، عدد را داخل `.env` قرار بده و بات را دوباره اجرا کن. چند مدیر را با ویرگول جدا کن. دستورهای مدیر فقط برای همان شناسه‌ها و در گفت‌وگوی خصوصی کار می‌کنند.

- شمارنده‌ها در SQLite بعد از restart حفظ می‌شوند؛ زمان اجرا و تعداد درخواست‌های ردشده مربوط به اجرای فعلی‌اند.
- فقط **۱۰٬۰۰۰ بررسی اخیر** نگه داشته می‌شود؛ شمارنده‌های تجمعی حفظ می‌شوند. زمان تاریخچه UTC است.
- تاریخچه فقط دامنه، وضعیت دو تحلیلگر، زمان بررسی و کد خطا را ذخیره می‌کند. متن پیام، توکن، مسیر و query لینک یا سورس صفحه ذخیره نمی‌شود.
- این تاریخچه **دیتاست آموزش مدل نیست**. بات ادعا نمی‌کند که لینک گزارش‌شده وارد دیتاست شده است.
- لاگ برنامه در `logs/bot.log` با سه نسخهٔ چرخشی یک‌مگابایتی نگه داشته می‌شود. متن لاگ‌ها انگلیسی است.

### ⚙️ تنظیمات

تمام تنظیمات در `.env.example` آمده‌اند؛ متغیرهای محیطی سرور بر `.env` اولویت دارند.

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `BOT_TOKEN` | الزامی | توکن جدید بات |
| `ADMIN_IDS` | خالی | شناسه‌های عددی مدیر؛ خالی یعنی مانیتورینگ تلگرامی غیرفعال |
| `REQUEST_TIMEOUT` | `10` | ثانیه برای یک دریافت و زنجیره redirect آن |
| `SCAN_TIMEOUT` | `40` | سقف ثانیه برای کل بررسی یک لینک |
| `MAX_CONCURRENT_SCANS` | `3` | تعداد درخواست‌های بررسی فعال؛ درخواست اضافی فوراً رد می‌شود |
| `MAX_URLS_PER_MESSAGE` | `3` | حداکثر لینک بررسی‌شده در هر پیام |
| `USER_COOLDOWN_SECONDS` | `5` | فاصلهٔ پذیرش درخواست‌های هر کاربر؛ درخواست هم‌زمان همان کاربر هم رد می‌شود |
| `MAX_EXTERNAL_SCRIPTS` | `4` | سقف فایل‌های خارجی؛ `0` یعنی غیرفعال، همراه گزارش ناقص بودن بررسی |
| `MAX_RESPONSE_BYTES` | `1048576` | سقف حجم **هر پاسخ**: پیش‌فرض یک MiB |
| `MONITOR_DB` | `data/monitor.sqlite3` | مسیر دیتابیس |
| `LOG_LEVEL` | `INFO` | سطح لاگ برنامه |

در حالت پیش‌فرض تنها پورت‌های عمومی `80` و `443` مجازند. آدرس خصوصی، loopback، metadata سرور و DNS دارای IP داخلی مسدود می‌شوند. مقصد redirect و اسکریپت‌های خارجی هم بررسی می‌شود. اعتبار TLS غیرفعال نشده و proxy محیطی استفاده نمی‌شود. سایت‌هایی که خودشان پشت CDN هستند همچنان مستقیم از آدرس اصلی دریافت می‌شوند؛ هیچ Worker واسطی در مسیر نیست.

### 🧪 بررسی کد و تست‌ها

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m pip check
```

تست‌ها محلی و با پاسخ‌های مصنوعی‌اند؛ به سایت فیشینگ واقعی یا بات واقعی درخواست نمی‌فرستند. تست یکپارچهٔ تلگرام هم با session ساختگی، چند لینک و دسترسی مدیر را بررسی می‌کند. جزئیات تغییرها در [گزارش دیباگ](docs/DEBUG_REPORT.md) آمده است.

### 🗂 نقشهٔ پروژه

| فایل | مسئولیت |
|---|---|
| `main_bot.py` | دریافت پیام، استخراج لینک، کنترل ظرفیت، پاسخ و دستورهای مدیر |
| `main.py` | نقطهٔ اجرای جایگزین |
| `config.py` | بارگذاری و اعتبارسنجی تنظیمات |
| `analyzer/http_client.py` | دریافت مستقیم، TLS، DNS، redirect و سقف حجم |
| `analyzer/enamad_checker.py` | بررسی پیوند اینماد |
| `analyzer/keylogger_detector.py` | تحلیل ایستای نشانه‌های خروج ورودی |
| `analyzer/scanner.py` | هماهنگی تحلیلگرها و حفظ شواهد در timeout |
| `analyzer/models.py` | مدل‌های نتیجه و وضعیت |
| `monitoring.py` | تاریخچه و شمارنده‌های SQLite |
| `tests/` | تست‌های دریافت، تحلیل، رابط و یکپارچگی |
| `deploy/anti-phishing-robot.service` | نمونهٔ اختیاری اجرای دائمی با systemd |

### 🔎 محدودیت‌های فعلی

جاوااسکریپت اجرا نمی‌شود؛ importهای تو‌در‌تو، iframe، service worker، ماژول پویا و مقصدهای دانلودشده در زمان اجرا بررسی نمی‌شوند. callback نام‌دار، arrow بدون آکولاد، template پیچیده و بعضی نحوهای جاوااسکریپت ممکن است شناسایی نشوند. این تحلیلگر parser یا موتور data-flow کامل نیست و ارسال ورودی در قابلیت‌هایی مانند جست‌وجوی زنده هم ممکن است نیازمند بازبینی دستی شود.

Packer، رشته‌های hex و API تلگرام به‌تنهایی هشدار توضیحی‌اند. نمادهای ساخته‌شده با JavaScript ممکن است قابل بررسی نباشند. صفحهٔ مرجع اینماد پویا یا captchaدار باشد، نتیجه نامشخص می‌شود. صفحات خالی، فایل باینری، پاسخ بسیار بزرگ یا فشرده‌ای که با وجود درخواست `identity` باز هم فشرده فرستاده شود، تحلیل نمی‌شوند. نتیجهٔ «موردی یافت نشد» فقط به بخش‌های قابل بررسی اشاره دارد.

برای اجرای دائمی، نمونهٔ [systemd](deploy/anti-phishing-robot.service) را با مسیر و کاربر واقعی سرورت تنظیم کن. راهنمای کوتاه داخل فایل است. برای ایدهٔ دیتاست ایرانی آینده، [این یادداشت](docs/DATASET_IDEA.md) را بخوان؛ جمع‌آوری و مدل هنوز پیاده‌سازی نشده‌اند.

---

## English

### ✨ What it does

Send the bot a suspicious URL or forwarded message. Your server fetches the page **directly**, checks eNamad seal links, and inspects a bounded subset of JavaScript for possible input exfiltration. No intermediary Worker, browser automation, ML model, or dashboard service is required.

| Feature | Behavior |
|---|---|
| Direct fetching | Main page fetched once and reused by both analyzers |
| Trust-seal checks | Exact official hostname validation and boundary-aware domain matching |
| Input exfiltration signals | Input reads and network calls in the same input/keyboard callback |
| External JavaScript | Up to four distinct files, including relative URLs and HTML `base` support |
| Explicit results | `suspicious`, `not_detected`, or `inconclusive` |
| Lightweight monitoring | Private admin commands, SQLite history, rotating English logs |
| Bounded resources | Time, body size, per-message URL limits, concurrency and per-user cooldown |

> **Interpretation:** This is a static, rule-based analyzer. Suspicion is not a confirmed keylogger verdict, and no detected signal is not a safety guarantee. Network errors, HTTP 403, missing seals, and invalid certificates do not independently establish phishing.

### 🚀 Quick start

Use **Python 3.11+**; this revision was tested with Python 3.12. Extract the revised ZIP and enter the directory containing `main_bot.py`. On Linux, install `python3-venv` if your distribution requires it.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

On Windows CMD:

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
copy .env.example .env
```

On PowerShell, activate with `.\.venv\Scripts\Activate.ps1` and copy with `Copy-Item .env.example .env`. If activation is blocked, use CMD or invoke `.\.venv\Scripts\python.exe` directly.

Edit `.env`:

```dotenv
BOT_TOKEN=YOUR_NEW_BOT_TOKEN
ADMIN_IDS=YOUR_NUMERIC_TELEGRAM_USER_ID
```

Start polling:

```bash
python main_bot.py
```

`python main.py` is an equivalent entry point. Run one polling process per token. Remove any previously configured Telegram webhook before starting polling.

**Rotate the original token:** The upstream repository exposed a bot credential. Revoke it with BotFather and use a new token. Removing the current source value does not remove it from Git history. This revision contains no real token and ignores `.env` in Git.

### 📊 Admin monitoring

| Command | Purpose |
|---|---|
| `/start` | Introduction |
| `/help` | Submission guide and result meanings |
| `/myid` | Your numeric Telegram user ID |
| `/status` | Process uptime, active work, cumulative counters and mean scan time |
| `/recent` | Ten latest scans: host, UTC timestamp, verdict and duration |
| `/errors` | Ten latest retained scans with fetch/analysis error codes |

Start with empty `ADMIN_IDS`, send `/myid` privately, add the returned ID to `.env`, and restart. Separate multiple admin IDs with commas. Admin commands require both an allowlisted sender and a private chat. An empty allowlist disables them.

SQLite preserves cumulative scan counters across restarts and retains the latest **10,000 scan events**. Uptime and rejected-request counts reset at process startup. Only hostname, analyzer statuses, timing, and stable error codes are stored. No original messages, paths, query strings, page source, or tokens are retained. This history is **not a training dataset**. Application logs use `logs/bot.log` with three one-MiB rotated backups. Telegram responses are Persian; code comments, docstrings and application logs are English.

### ⚙️ Configuration

Process environment values override `.env`. See `.env.example` for all settings.

| Variable | Default | Meaning |
|---|---|---|
| `BOT_TOKEN` | Required | New bot credential |
| `ADMIN_IDS` | Empty | Comma-separated numeric admin IDs |
| `REQUEST_TIMEOUT` | `10` | Seconds per fetch, including redirects |
| `SCAN_TIMEOUT` | `40` | Seconds for the entire URL scan |
| `MAX_CONCURRENT_SCANS` | `3` | Active scan requests; excess work rejected immediately |
| `MAX_URLS_PER_MESSAGE` | `3` | Maximum URLs analyzed per message |
| `USER_COOLDOWN_SECONDS` | `5` | Per-user admission cooldown; overlapping requests also rejected |
| `MAX_EXTERNAL_SCRIPTS` | `4` | External JS file limit; skipped files make the check inconclusive |
| `MAX_RESPONSE_BYTES` | `1048576` | Maximum bytes per response |
| `MONITOR_DB` | `data/monitor.sqlite3` | SQLite file location |
| `LOG_LEVEL` | `INFO` | Application logging level |

Only HTTP(S) on ports 80/443 is fetched. Private, loopback, metadata and mixed public/private DNS destinations are rejected, including script and redirect targets. The checked DNS answers are used by the connector, TLS verification remains enabled, and environment proxies are ignored. Websites hosted behind a CDN remain reachable through their original URLs; no intermediary Worker is used.

### 🧪 Development checks

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m pip check
```

Tests use synthetic fixtures and mocked network/Telegram responses. They do not contact live phishing sites or a real bot. See the [debug report](docs/DEBUG_REPORT.md) for the scope and verification results.

### 🔎 Current limitations

No JavaScript execution, browser sandbox, complete JavaScript parser, data-flow analysis, nested module/import traversal, iframe inspection, or full malware detection is provided. Named callbacks, expression arrows, complex templates and some syntax can be missed. Legitimate live search can resemble the callback heuristic and requires manual review.

Obfuscation and Telegram endpoints alone are informational warnings. Dynamic seals, captcha-protected references and failed script downloads may produce inconclusive checks. Binary, oversized, empty or forcibly compressed responses are not analyzed. A clean result covers only fetched, supported content and never certifies a website.

Optional Linux service: customize [the systemd example](deploy/anti-phishing-robot.service) for your host. Future Iranian phishing dataset design is described in [this note](docs/DATASET_IDEA.md); no collector or ML training pipeline has been added.

### 📚 References

- [aiogram documentation](https://docs.aiogram.dev/en/latest/)
- [aiohttp client documentation](https://docs.aiohttp.org/en/stable/client_advanced.html)
- [Original repository](https://github.com/mobina-hsz/anti-phishing-robot)

### 📄 License

MIT. The upstream [LICENSE](LICENSE) and attribution are preserved.
