# إعداد Firebase Authentication لمشروع CloudSOC

## ما الذي تم ربطه؟
- تسجيل حساب جديد باستخدام البريد الإلكتروني وكلمة المرور فقط.
- تسجيل الدخول باستخدام البريد الإلكتروني وكلمة المرور.
- إعادة تعيين كلمة المرور عبر البريد الإلكتروني.
- التحقق من Firebase ID Token في الخادم باستخدام Firebase Admin SDK.
- إنشاء مستخدم محلي تلقائيًا بدور `SECURITY_ANALYST` عند أول تسجيل ناجح.
- الإبقاء على SQLite كمصدر بيانات CloudSOC، وعلى حسابات Admin/Analyst التجريبية المحلية.
- لا يتم استخدام Firestore في هذا التكامل؛ لأنه غير مطلوب لإدارة تسجيل الدخول.

## 1) تفعيل Email/Password في Firebase
1. افتح Firebase Console ثم مشروع `cloudsoc-5f44a`.
2. افتح Authentication ثم Get started.
3. افتح Sign-in method (أو Providers).
4. فعّل Email/Password ثم Save.
5. من Authentication > Settings > Authorized domains تأكد من وجود `localhost` للتجربة المحلية. عند النشر لاحقًا أضف نطاق Netlify أيضًا.

## 2) إعداد Firebase Web App
انسخ القيم من Firebase Console > Project settings > Your apps > Web app، وضعها في ملف `.env` الموجود بجوار `package.json`:

```env
VITE_FIREBASE_API_KEY=ضع_apiKey_هنا
VITE_FIREBASE_AUTH_DOMAIN=ضع_authDomain_هنا
VITE_FIREBASE_PROJECT_ID=cloudsoc-5f44a
VITE_FIREBASE_STORAGE_BUCKET=ضع_storageBucket_هنا
VITE_FIREBASE_MESSAGING_SENDER_ID=ضع_messagingSenderId_هنا
VITE_FIREBASE_APP_ID=ضع_appId_هنا
```

هذه قيم إعداد Web SDK. لا تضع ملف Service Account في مجلد `src` ولا في الواجهة.

## 3) إعداد Firebase Admin للخادم
1. في Firebase Console افتح Project settings > Service accounts.
2. اختر Generate new private key ونزّل ملف JSON.
3. أعد تسمية الملف إلى `firebase-service-account.json`.
4. ضعه في جذر مشروع Node/React نفسه، بجوار `package.json` و`.env`.
5. أضف إلى `.env`:

```env
FIREBASE_PROJECT_ID=cloudsoc-5f44a
FIREBASE_SERVICE_ACCOUNT_PATH=./firebase-service-account.json
```

على بيئة استضافة سحابية يمكن استخدام متغير سرّي `FIREBASE_SERVICE_ACCOUNT_JSON` بدل ملف المفتاح، إذا كانت منصة الاستضافة تدعم حفظ أسرار JSON متعددة الأسطر بأمان.

**أمان مهم:** ملف `firebase-service-account.json` يحتوي مفتاحًا خاصًا. لا ترسله في المحادثات، ولا ترفعه إلى GitHub، ولا تضعه داخل `src`. تمت إضافته إلى `.gitignore`.

## 4) تثبيت الحزم
افتح PowerShell داخل المجلد الذي يحتوي `package.json`، ثم نفّذ:

```powershell
npm install firebase firebase-admin
```

استخدم `npm install` في أول مرة بعد إضافة الحزمتين حتى يتم تحديث `package-lock.json`. بعد ذلك يمكن استخدام `npm ci` في التثبيتات اللاحقة.

## 5) تشغيل التطبيق
```powershell
npm run dev
```
افتح الرابط الذي يظهر في Terminal، وغالبًا `http://localhost:3000`.

إذا ظهر خطأ 503 بعد أن تم إنشاء حساب Firebase بالفعل، فهذا يعني غالبًا أن إعداد Firebase Admin في الخادم غير مكتمل. أضف ملف Service Account ومتغيراته ثم أعد تشغيل الخادم، وبعدها استخدم صفحة Sign In بنفس البريد وكلمة المرور؛ لا تحاول إنشاء الحساب مرة ثانية.

## 6) اختبار التسجيل
1. افتح Create an account.
2. أدخل البريد الإلكتروني وكلمة المرور فقط.
3. يجب أن ينشأ الحساب في Firebase Console > Authentication > Users.
4. يجب أن ينشأ سجل محلي للمستخدم في SQLite بدور `SECURITY_ANALYST`.
5. سجّل الخروج ثم ادخل بنفس البريد وكلمة المرور.
6. جرّب Forgot password لإرسال رابط إعادة تعيين كلمة المرور.

## حسابات العرض القديمة
حسابا `admin@cloudsoc.local` و`analyst@cloudsoc.local` يظلان على تسجيل الدخول المحلي القديم حتى لا تتغير صلاحياتهما. تسجيل Firebase لا يستطيع الاستيلاء على بريد موجود مسبقًا في SQLite؛ يلزم ربطه إداريًا بشكل منفصل إذا رغبت في تحويله لاحقًا.

## ملاحظات وحدود
- Firebase Authentication يدير هوية وكلمة مرور المستخدم، بينما جلسة CloudSOC وصلاحياته وبياناته التشغيلية تظل في الخادم وSQLite.
- الحسابات الجديدة تُمنح `SECURITY_ANALYST` تلقائيًا؛ لا توجد طريقة تسجيل عام تمنح ADMIN.
- لا يلزم إنشاء Firestore لهذا السيناريو.
- عند النشر على Netlify أو أي استضافة أخرى، يجب إضافة متغيرات `VITE_FIREBASE_*` إلى إعدادات البناء، وإعداد `FIREBASE_SERVICE_ACCOUNT_PATH` أو `FIREBASE_SERVICE_ACCOUNT_JSON` في بيئة الخادم، وإضافة نطاق الموقع إلى Firebase Authentication > Settings > Authorized domains.
- لا تعتبر التكامل مكتملًا حتى تنجح تجربة التسجيل والدخول وإعادة تعيين كلمة المرور على جهازك.
