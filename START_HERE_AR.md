# CloudSOC — ابدأ من هنا (تعليمات بالعربي المصري)

## الملف ده فيه إيه؟
- الكود الفعلي للنسخة اللي هتعرضوها للدكتور: React + TypeScript + Node.js + Express + SQLite.
- خمس قواعد كشف، Dashboard، Events، Alerts، Incidents، Threat Intelligence، Reports، Audit، Users، Settings، Profile.
- اختبارات آلية، وملف توضيح للحدود الفنية، وملف Docker اختياري للتشغيل المحلي.

## إزاي أشغله؟
1. فك الضغط كاملًا. افتح مجلد **CloudSOC** اللي جواه `package.json`.
2. ثبّت Node.js 22.16 أو إصدار أحدث من 22.x من موقع Node.js الرسمي.
3. لإعداد Firebase Authentication، اتبع أولًا `FIREBASE_AUTH_SETUP_AR.md`. أضف قيم Firebase Web إلى `.env`، وضع ملف Service Account الآمن بجوار `package.json`.
4. على Windows اضغط مرتين `RUN_CLOUDSOC_WINDOWS.bat`، أو افتح PowerShell في مجلد المشروع واكتب:

```powershell
Copy-Item .env.example .env  # إذا لم يكن ملف .env موجودًا فقط
npm install firebase firebase-admin
npm run dev
```

أول أمر تثبيت يحدّث `package-lock.json` بالحزم الجديدة. بعد ذلك يمكن استخدام `npm ci` للتثبيت النظيف.

4. افتح **http://localhost:3000**، ومن الـLogin استخدم زر **Use Admin Demo** ثم **Sign In**.
5. لو عايز تتأكد إن السيرفر شغال، افتح **http://localhost:3000/api/health** ولازم تشوف `status: healthy`.
6. لأول تثبيت لازم إنترنت لتنزيل الحزم. ما تنقلش `node_modules` من جهاز تاني.

## Demo للدكتور (الترتيب)
1. Login → Dashboard (6 KPIs / 5 charts).
2. Security Events → Run Brute-Force Test بــ IP تجريبي جديد مثل `198.51.100.245` و10 محاولات.
3. Detection Engine → RULE-002 وRULE-001.
4. Alerts → اختار التنبيه وعيّن Analyst واكتب Note ثم Escalate.
5. Incidents → حرك الحالة NEW ثم INVESTIGATING ثم CONTAINED ثم RESOLVED وسجل Response Action.
6. Threat Intelligence → جرّب IPv4 `185.220.101.42` (Local Demonstration Mode).
7. Reports → صدّر CSV وPDF؛ Audit Logs → شوف أثر الإجراءات.

**مهم:** أي Brute-Force هنا محاكاة دفاعية جوه النظام فقط، وResponse Actions سجلات يدوية مش أوامر Firewall.

## اختبارات قبل المناقشة

```powershell
npm run lint
npm test
npm run build
```

النسخة دي اجتازت 24 اختبار Node وTypeScript check في بيئة المراجعة؛ اختبار بناء Vite من تثبيت نظيف محتاج يتعمل على جهازكم لأن بيئة المراجعة ما فيهاش وصول لشبكة npm.

## أوضح حدود المشروع من غير إحراج
- النسخة العاملة هي Node/React/SQLite. Python/Flask/PostgreSQL جزء مرجعي غير مكتمل، مش النسخة اللي هتشغلوها.
- مفيش نشر Cloud عام متحقق أو CloudTrail live connector.
- Threat Intel بيستخدم Local Demonstration Mode لو API keys مش موجودة.
- قواعد الكشف Rule-Based، مش AI/ML.
- حسابات العرض معروفة؛ ممنوع تعرضوا التطبيق على الإنترنت بالحسابات دي.
