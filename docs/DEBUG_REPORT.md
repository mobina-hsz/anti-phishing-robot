# Debug report | گزارش اصلاح و بررسی

Upstream revision: `63162c7` · Prepared: 2026-10-08 · Runtime used: Python 3.12

## فارسی

### تغییرهای اصلی

| ایراد قبلی | اصلاح |
|---|---|
| صفحه و پیوند اینماد با الحاق URL به Worker دریافت می‌شدند | تمام دریافت‌ها از URL اصلی و با یک HTTP client مشترک برای هر بررسی انجام می‌شوند |
| دامنه‌های مشهور از بررسی اصلی معاف می‌شدند | shortcut حذف شد؛ دامنه مشهور هم از مسیر تحلیل معمول عبور می‌کند |
| دو فایل زیرساخت هم‌نام و ناسازگار وجود داشت | هر دو فایل بلااستفاده حذف شدند؛ فراخوانی‌ها و import مربوط هم حذف شدند |
| TLS بدون اعتبارسنجی استفاده می‌شد | اعتبارسنجی TLS فعال است؛ خطای گواهی نتیجه نامشخص دارد |
| هر 403/timeout به فیشینگ تبدیل می‌شد | وضعیت دریافت ناقص از نشانهٔ جعل جدا شد |
| خطای بررسی کی‌لاگر گاهی «امن» گزارش می‌شد | خطا یا اسکریپت دریافت‌نشده نتیجه نامشخص می‌سازد |
| رویداد کیبورد و fetch بی‌ربط در یک فایل کافی بود | الگوی خواندن ورودی و ارسال شبکه داخل یک callback بررسی می‌شود |
| جاوااسکریپت خارجی و handler داخل HTML دیده نمی‌شد | فایل خارجی محدود، مسیر نسبی، base و handlerهای متداول اضافه شدند |
| نمونه‌کد داخل رشته و comment باعث هشدار می‌شد | commentها حذف و matchهای داخل رشته‌های متنی در قواعد رفتاری نادیده گرفته می‌شوند |
| ساخت XMLHttpRequest بدون ارسال کافی بود | ارسال `.send(...)` بررسی می‌شود؛ صرف ساخت XHR کافی نیست |
| Packer/hex یا API تلگرام اثبات کی‌لاگر محسوب می‌شد | این موارد به‌تنهایی هشدار توضیحی‌اند |
| میزبان نماد با substring بررسی می‌شد | میزبان رسمی باید دقیقاً `trustseal.enamad.ir` باشد؛ redirect مرجع هم به همان میزبان محدود است |
| تطبیق دامنه با substring بود | مرز دامنه کنترل می‌شود؛ `fake-shop.ir` با `shop.ir` یکسان نیست |
| نبود نماد در سامانهٔ دولتی باعث فیشینگ می‌شد | نبود نماد به‌تنهایی حکم فیشینگ ایجاد نمی‌کند |
| توکن واقعی داخل کد بود | بارگذاری از `.env`/environment؛ توکن واقعی در خروجی وجود ندارد |
| نتیجه چند لینک روی یک پیام بازنویسی می‌شد | هر لینک پیام وضعیت و نتیجهٔ جداگانه دارد |
| HTML خروجی از URL خام ساخته می‌شد | متن‌های متغیر escape و طول نمایش محدود می‌شود؛ preview لینک هم غیرفعال است |
| ادعای ذخیرهٔ آموزشی بدون ذخیره‌سازی وجود داشت | حذف ادعا؛ تاریخچهٔ واقعی مانیتورینگ با دامنه و وضعیت ذخیره می‌شود |
| `main.py` فقط آزمایش SSL بود | حالا نقطهٔ اجرای معتبر بات است |
| requirements و راهنمای کافی نبود | requirements اجرای اصلی/توسعه، README دوزبانه، نمونه env و systemd اضافه شدند |
| فایل‌های pyc داخل Git بودند | فایل‌های کامپایل‌شده حذف و ignore شدند |

### مانیتورینگ

`/status`، `/recent` و `/errors` فقط برای شناسه‌های مدیر در گفت‌وگوی خصوصی فعال‌اند. SQLite تاریخچهٔ محدود به ۱۰٬۰۰۰ بررسی و شمارنده‌های تجمعی را حفظ می‌کند. لاگ‌ها انگلیسی، چرخشی و بدون query لینک یا متن exception خام‌اند. تاریخچه، دیتاست آموزشی محسوب نمی‌شود. داشبورد وب یا dependency پایش جداگانه اضافه نشده است.

### نتیجهٔ بررسی‌ها

| بررسی | نتیجه |
|---|---|
| `python -m pytest -q` | **81 passed** |
| `python -m ruff check .` | بدون خطا |
| `python -m compileall` روی فایل‌های برنامه و تست | موفق |
| `python -m pip check` | No broken requirements found |
| بررسی کد برنامه برای Worker endpoint و غیرفعال‌سازی TLS | موردی وجود ندارد |
| بررسی کد برنامه برای توکن بات جاسازی‌شده | توکن واقعی وجود ندارد |
| تست یکپارچه HTTP با سرور محلی | دریافت مستقیم، redirect، فایل JS و نتیجهٔ مشکوک موفق |
| تست یکپارچه Telegram با session ساختگی | پاسخ جداگانهٔ چند لینک و اجازهٔ مدیر موفق |
| تلاش دریافت مستقیم دو سایت عمومی | `dns_error` در محیط اجرا؛ اتصال اینترنتی واقعی تأیید نشد |
| polling روی Telegram واقعی | اجرا نشد؛ توکن افشاشده استفاده نشد |

تست‌ها عملکرد مسیرهای اصلاح‌شده را بررسی می‌کنند؛ دقت تشخیص روی مجموعهٔ واقعی فیشینگ ایرانی اندازه‌گیری نشده است. این خروجی را روی سرورت با توکن جدید راه‌اندازی و چند نمونهٔ سالم و مصنوعی بررسی کن. سیاست شبکهٔ سرور، دسترسی به تلگرام و مرجع اینماد می‌تواند بر نتیجهٔ دریافت اثر بگذارد.

### تغییر رابط داخلی

تحلیلگرها دیگر tuple بولی برنمی‌گردانند. `check_enamad(page, fetcher)` و `check_keylogger(page, fetcher)` یک `CheckResult` با status/reason/warnings می‌دهند. برای استفاده از بیرون بات، `await scan_url(url, settings)` رابط اصلی است و `ScanResult` می‌دهد. این تغییر برای جداکردن «نامشخص» از «بدون نشانه» لازم بود.

### کار باقی‌مانده برای آینده

مدل ML، crawler، دیتاست و تحلیل مرورگر پیاده‌سازی نشده‌اند. پیشنهاد دیتاست در [DATASET_IDEA.md](DATASET_IDEA.md) است. محدودیت‌های detector ایستا در README مستند شده‌اند. تغییرها فقط در نسخهٔ تحویلی اعمال شده‌اند؛ به رپوی GitHub push نشده‌اند. توکن قدیمی در upstream عمومی و تاریخچه آن باقی است و باید از BotFather باطل شود.

---

## English

### Changes

- Removed all intermediary Worker requests and both obsolete infrastructure modules, including the well-known-domain bypass.
- Added a shared per-scan direct HTTP client with verified TLS, checked public DNS answers, revalidated redirects, body/time limits and no environment proxies.
- Introduced explicit suspicious, not-detected and inconclusive results; network failures cannot become safety or phishing verdicts by themselves.
- Reworked static input-exfiltration signals: correlate input reads and transmission within callbacks, inspect bounded external scripts and HTML handlers, and ignore comments/quoted code examples. XHR construction alone does not establish transmission.
- Downgraded obfuscation and Telegram API presence to standalone warnings. No token values are exposed in scan output.
- Tightened official trust-seal hostname and domain-boundary checks. Missing seals and unavailable reference pages do not prove phishing.
- Fixed independent multi-link responses, hidden-link/UTF-16 extraction, HTML escaping, length limits, session shutdown and the application entry point.
- Moved bot credentials to environment configuration; removed tracked bytecode.
- Added private admin commands, bounded SQLite event history, cumulative counters, rotating English logs, validated settings, runtime/dev requirements, bilingual README and optional systemd sample.

### Verification

**81 tests passed** on Python 3.12. Ruff, compile checks and `pip check` passed. Tests cover conservative detector decisions, exact seal-host/domain matching, public/private address checks, redirect blocking, response limits, scan outcomes, URL entities, admission limits, monitoring persistence, multiple Telegram responses and admin authorization.

An actual local HTTP fixture validated the direct request/redirect/script transport. Its resolver is substituted only inside that test; production public-address checks remain enabled. Telegram integration uses an in-memory fake session and never uses a real credential.

Attempts to fetch two public reference sites directly returned `dns_error` in this execution environment. Live Internet transport and real Telegram polling were therefore not verified. The exposed upstream credential was deliberately not used. No accuracy benchmark against a real labeled Persian phishing corpus was performed.

### Compatibility and scope

Analyzer functions now accept a fetched `Page` plus `Fetcher` and return `CheckResult` instead of a boolean tuple. Use `await scan_url(url, settings)` as the top-level Python API. No ML model, dataset collector or browser analysis was added. Code limitations and interpretation are documented in README. Changes were not pushed to upstream GitHub. Revoke the upstream credential with BotFather before deploying.
