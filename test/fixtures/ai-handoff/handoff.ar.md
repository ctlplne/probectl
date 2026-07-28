<!-- probectl-ai-handoff/v1; lang=ar; dir=rtl -->
# تسليم تحقيق Ask من probectl

> **ملاحظة تحقيق آنية وغير مرجعية\. هذا الملف نسخة محلية من إجابة واحدة مقيّدة بالمستأجر وصلاحيات RBAC\. قد تتقادم الأدلة، وقد تتغير الصلاحيات، وقد تُحفظ سجلات المصدر أو تُحذف\. أعد فتح probectl وأعد التحقق من صلاحية كل مصدر مستشهد به قبل اتخاذ قرار\.**

## الإيصال

- **العقد:** ` probectl-ai-handoff/v1 `
- **معرّف الإجابة:** ` ans/incident #42 `
- **المستأجر:** ` tenant-acme `
- **السؤال:** Why did checkout \*slow\* after \[change\]?
- **الثقة:** ` high `
- **الأدلة غير كافية:** لا
- **مسار احتياطي متدهور:** نعم
- **النموذج:** ` builtin `
- **مهايئ الاستدلال:** ` builtin `
- **تنفيذ الاستدلال:** ` builtin_fallback `
- **موافقة خروج البيانات:** ` granted `
- **المهايئ الذي تمت محاولته:** ` openai:operator-model `
- **الادعاءات السببية المحجوبة:** ١

## السبب الجذري الموثق

> A BGP route change diverted checkout traffic through a congested transit\.

- **الاستشهادات:** [E1](#evidence-1)

## النتائج الموثقة

١. The route changed before latency rose\.
   - **الاستشهادات:** [E1](#evidence-1), [E2](#evidence-3)
٢. Checkout latency crossed the warning threshold\.
   - **الاستشهادات:** [E2](#evidence-3)

## خطة التحقيق للقراءة فقط

١. Check the exact incident and its correlated signals\.
   - **النطاق:** ` entities `
   - **الحالة:** ` queried `
   - **للقراءة فقط:** نعم
   - **الحد:** ٥٠
   - **عدد الأدلة:** ٢
   - **مقتطع:** لا
   - **المحدِّد:** ` {"incident_id":"inc-42","target":"checkout.example"} `
   - **العقدة:** ` service:checkout `
   - **النافذة الزمنية:** ` 2026-07-28T08:00:00Z — 2026-07-28T09:00:00Z `
٢. Check change and routing events near the selected window\.
   - **النطاق:** ` events `
   - **الحالة:** ` blocked `
   - **للقراءة فقط:** نعم
   - **الحد:** ٥٠
   - **عدد الأدلة:** ٠
   - **مقتطع:** لا
   - **السبب:** RBAC denied this read\.
٣. Check bounded service metrics\.
   - **النطاق:** ` metrics `
   - **الحالة:** ` skipped `
   - **للقراءة فقط:** نعم
   - **الحد:** ٢٥
   - **عدد الأدلة:** ٠
   - **مقتطع:** نعم
   - **السبب:** The source is not configured\.

## الأدلة حسب المستوى

### bgp

<a id="evidence-1"></a>
#### E1 — Route changed for 192\.0\.2\.0/24

- **النطاق:** ` entities `
- **الحالة:** ` critical `
- **وقت الحدوث:** ` 2026-07-28T08:15:00Z `
- **المصدر:** ` bgp://event/route-42 `
- **الملخص:** AS64501 announced a more\-specific route\.
- **مستشهد به في:** السبب الجذري, النتيجة ١
- **الحقول:** ` {"as_path":[64500,64501],"origin_asn":64501,"prefix":"192.0.2.0/24"} `

### change

<a id="evidence-2"></a>
#### E3 — Deployment completed

- **النطاق:** ` events `
- **وقت الحدوث:** ` 2026-07-28T08:10:00Z `
- **المصدر:** غير مسجّل
- **الملخص:** The application deployment completed without an error\.
- **مستشهد به في:** غير مسجّل
- **الحقول:** ` {"deployment":"checkout-2026-07-28.1","status":"succeeded"} `

### metrics

<a id="evidence-3"></a>
#### E2 — Checkout p95 latency

- **النطاق:** ` metrics `
- **الحالة:** ` warning `
- **وقت الحدوث:** ` 2026-07-28T08:17:30.123Z `
- **المصدر:** ` metric://checkout/p95 `
- **الملخص:** p95 reached 940 ms &amp; remained elevated\.
- **مستشهد به في:** النتيجة ١, النتيجة ٢
- **الحقول:** ` {"labels":{"service":"checkout","site":"blr-1"},"unit":"ms","value":940} `

## القيود

> **هذا التسليم دليل، وليس حالة مرجعية مباشرة أو موافقة على معالجة أو إذنا بالتصرف\. تحقّق من القياسات والصلاحيات والسياق التشغيلي الحالي في probectl\.**
