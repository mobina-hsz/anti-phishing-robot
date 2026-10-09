# Future dataset idea | ایدهٔ دیتاست آینده

## فارسی

**ایده: «بانک نمونه‌های تأییدشدهٔ فیشینگ فارسی با تاریخ و خانوادهٔ حمله».** ارزش دیتاست به لینک زیاد نیست؛ به برچسب درست، شاهد قابل بازبینی و جلوگیری از نشت بین train و test است. این سند صرفاً پیشنهاد آینده است؛ هیچ جمع‌آوری یا آموزشی در این نسخه فعال نشده است.

### ۱. ورودی‌های پیشنهادی

گزارش داوطلبانهٔ کاربران همین بات، نمونه‌های منتشرشده در هشدارهای عمومی و منابعی که اجازهٔ استفاده از داده‌شان را می‌دهند. برای گزارش کاربر، رضایت و سازوکار حذف داده داشته باش. پیامک خام می‌تواند شماره، کد ملی یا شناسهٔ فردی داشته باشد؛ این موارد را قبل از نگهداری حذف کن. فهرست دامنه‌های گزارش‌شده را مستقیماً «فیشینگ قطعی» برچسب نزن.

### ۲. سه برچسب به‌جای دو برچسب عجولانه

| برچسب | شرط پیشنهادی |
|---|---|
| `phishing_confirmed` | شواهد جعل هویت و گرفتن اطلاعات حساس؛ بررسی انسانی یا منبع معتبر ثبت‌شده |
| `benign_verified` | شواهد مستقل از واقعی بودن خدمت در زمان مشاهده؛ شامل نمونه‌های شبیه فیشینگ |
| `unknown` | سایت مرده، گزارش بدون شاهد، نتایج متناقض یا محتوای غیرقابل دریافت |

از خروجی همین detector به‌عنوان حقیقت آموزشی استفاده نکن؛ مدل صرفاً اشتباهات فعلی آن را یاد می‌گیرد. نمونه‌های مبهم را برای بازبینی نگه دار و وارد train دارای برچسب قطعی نکن. برای نمونه‌های دشوار، دو بازبین و ثبت اختلاف نظر مفید است.

### ۳. شواهدی که بعداً ارزش دارند

پیشنهاد رکورد: شناسه، زمان اولین مشاهده، زمان برداشت، منبع، URL پالایش‌شده، هش URL اصلی در صورت مجاز بودن نگهداری، دامنه، زنجیره redirect، وضعیت HTTP، برند تقلیدشده، خانوادهٔ حمله، ویژگی‌های URL و HTML، هش محتوا، برچسب، دلیل، بازبین و نسخهٔ ابزار جمع‌آوری. هش URL به‌تنهایی ناشناس‌سازی کامل نیست؛ دادهٔ حساس را حتی در نسخه‌های پشتیبان کنترل کن.

برای مدل URLمحور، URL و ساختار دامنه مهم‌اند. برای مدل محتوایی، snapshot ایستای HTML/JS در زمان مشاهده ارزش بیشتری از یک لینک مرده دارد. جمع‌آوری محتوا را در محیط جدا و محدود انجام بده، JavaScript را در سرور اصلی اجرا نکن و دادهٔ حساس وارد فرم‌ها نکن. تصویر یا نمونهٔ خام اگر حاوی اطلاعات شخصی بود، قبل از اشتراک‌گذاری پالایش شود.

### ۴. بخش مهم: نمونهٔ سالمِ سخت

سامانه‌های واقعی قضایی و دولتی، فروشگاه‌های کوچک بدون نماد قابل خواندن، سایت‌های HTTP قدیمی، دامنه‌های طولانی، loginهای قانونی، جست‌وجوی زنده، سایت‌های دارای کد minified و سایت‌های سالم ولی موقتاً قطع، «negative»های ارزشمندی‌اند. دامنهٔ `.ir` یا وجود/نبود اینماد نباید خودش برچسب بسازد. توزیع فارسی، نوع پیامک و برندها را هم در نمونه‌های سالم و هم مخرب متنوع نگه دار.

### ۵. تفکیک درست و ارزیابی

URLهای تکراری و قالب‌های تقریباً یکسان را حذف یا گروه‌بندی کن. دامنهٔ ثبت‌شده، خانوادهٔ حمله و هش/شباهت قالب باید در تفکیک گروهی لحاظ شوند؛ یک clone از همان صفحه در train و test نباشد. برای تشخیص دامنهٔ ثبت‌شده از ابزار مبتنی بر Public Suffix List استفاده کن، نه «دو بخش آخر» دامنه.

یک test زمانی از نمونه‌های جدیدتر، جدا از train نگه دار. معیارهای مناسب: precision، recall، PR-AUC، نرخ اخطار اشتباه روی نمونه‌های سالم سخت و عملکرد به تفکیک خانوادهٔ حمله. برای یک بات عمومی، precision و گزارش صادقانهٔ unknown اهمیت عملی زیادی دارند. ابتدا با یک baseline ساده مثل TF-IDF روی اجزای URL و مدل خطی شروع کن؛ بعد ارزش افزودن محتوا یا مدل بزرگ‌تر را بسنج.

**شروع پیشنهادی:** یک مجموعهٔ کوچک از نمونه‌های انسانیِ تأییدشده و نمونه‌های سالمِ سخت تهیه کن، دستورالعمل برچسب‌گذاری را ثابت کن و بعد حجم را بالا ببر. عدد بزرگ بدون کیفیت، مدل قابل اعتماد نمی‌سازد.

---

## English

**Idea: a time-stamped, evidence-backed Persian phishing corpus grouped by campaign.** This is a future design note; no collection or training has been implemented.

- Collect opt-in reports, public warnings and permitted feeds. Record source and observation dates. Remove personal data before retention; provide consent and deletion mechanisms.
- Use `phishing_confirmed`, `benign_verified` and `unknown`. Human evidence or a documented trustworthy source determines labels. Do not use this bot's predictions as ground truth.
- Keep sanitized URLs, redirect chains, HTTP status, claimed brand, campaign family, content hashes, feature snapshots, reviewer rationale and collector version. Original URL hashes are not guaranteed anonymization. Collect static content in an isolated environment, without executing remote code or submitting sensitive data.
- Include hard benign negatives: government pages without seals, small shops, long URLs, legitimate login/live-search pages, obfuscated/minified scripts, HTTP sites and temporary outages. Neither `.ir` nor a missing trust seal determines a label.
- Deduplicate by URL, registrable domain, campaign and template similarity. Use a Public Suffix List implementation to identify registrable domains. Keep related clones in the same split and reserve a later time period for testing.
- Measure precision, recall, PR-AUC and false positives on hard benign examples. Track results per campaign. Start with a URL-feature or character/token TF-IDF baseline and a linear model before investing in larger models.

A smaller corpus with defensible labels is more useful than a large collection of unverified links.
