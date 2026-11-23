# فين أرفع المشروع للدكتور؟

كلمة **ارفعوه** ممكن يكون قصد الدكتور بيها حاجة من 3:

1. **تسليم ملفات للمقرر:** ادخل على منصة الجامعة (Moodle/Blackboard/Teams/Google Classroom حسب مقررك)، اختار مادة Cloud Computing ثم Assignment/Project Submission ثم Upload وارفع ZIP أو الملفات اللي طلبها. اتأكد إن الحالة Submitted/Turned in، واحتفظ بصورة التأكيد.
2. **رفع Source Code على GitHub:** اعمل Repository جديد **Private**، ارفع ملفات مجلد CloudSOC من غير `node_modules` ولا `.env` ولا SQLite خاصة. لو الدكتور هيشوف المشروع على GitHub، ضيفه Collaborator أو شارك الرابط بالطريقة اللي حددها. ملف ZIP ده ينفع كـSource؛ بس متعملش Repository Public بالحسابات التجريبية الموجودة.
3. **نشر موقع شغال أونلاين:** ده Deployment مختلف عن تسليم ZIP أو GitHub. المشروع حاليًا بيستخدم SQLite وحسابات عرض ثابتة؛ نشره للعموم محتاج أمان وتخزين دائم وخطة Deployment مناسبة، ومينفعش ندّعي إنه اتنشر دلوقتي.

## إيه الملفات اللي أسلمها؟

- **CloudSOC_Ready_For_Defense.zip**: الكود الجديد المنظف + التوثيق والعرض + دليل التشغيل.
- أو لو منصة الدكتور بتطلب ملفات منفصلة: `CloudSOC_Presentation_SUBMISSION.pptx` و`CloudSOC_Documentation_SUBMISSION.docx` و`CloudSOC_Source_Code.zip`.

## آخر مراجعة قبل رفع الملفات

- افتح المشروع على جهازكم وشغّل `npm ci` و`npm test` و`npm run dev` ثم سيناريو Demo.
- اتأكد من اسم المشرف وتاريخ التسليم الرسمي إذا كان مطلوبين؛ ما تمش اختراعهم.
- اتأكد من تعليمات الدكتور: هل المطلوب Code ZIP، أو GitHub Link، أو Live Website URL؟
- متبعتش كلمة مرور `.env` ولا مفاتيح API ولا قاعدة بيانات فيها بيانات شخصية.
