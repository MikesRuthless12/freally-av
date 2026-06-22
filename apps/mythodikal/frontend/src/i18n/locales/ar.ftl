# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = إلغاء
button-confirm = تأكيد
button-save = حفظ
button-close = إغلاق
button-scan-now = افحص الآن
button-pause = إيقاف مؤقت
button-resume = استئناف
button-stop = إيقاف
button-retry = إعادة المحاولة
button-export-bundle = تصدير حزمة التشخيص

## Navigation

nav-scan = الفحص
nav-history = السجل
nav-quarantine = الحجر
nav-exclusions = الاستثناءات
nav-realtime = الوقت الفعلي
nav-usb-devices = أجهزة USB
nav-settings = الإعدادات

## Scan page

scan-title = الفحص
scan-status-idle = خامل
scan-status-running = جارٍ الفحص…
scan-status-paused = متوقف مؤقتًا
scan-status-cancelled = أُلغي
scan-status-completed = اكتمل
scan-files-visited = تم فحص { $count } ملف
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = لا توجد نتائج
scan-findings-summary-one = نتيجة واحدة
scan-findings-summary-other = { $count } نتيجة

## Real-time

realtime-mode-fsevents-observe = FSEvents (مراقبة)
realtime-mode-fanotify-full = fanotify (كامل)
realtime-mode-fanotify-observe = fanotify (مراقبة)
realtime-mode-audit-fallback = الرجوع إلى audit (مراقبة فقط)
realtime-mode-inotify-fallback = الرجوع إلى inotify (مراقبة فقط)
realtime-shields-on = الحماية في الوقت الفعلي: مُفعّلة
realtime-shields-off = الحماية في الوقت الفعلي: مُعطّلة

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = حزمة التشخيص
settings-about-bundle-help = صدّر ملف zip يحتوي على سجلات المحرّك الأخيرة وإعدادات التشغيل لديك. تتم إزالة مسارات الفحص قبل كتابة الحزمة. أرفقها بمشكلة على GitHub عند الإبلاغ عن خلل.

## Settings — scheduler (TASK-086)

settings-scheduler-title = عمليات الفحص المجدولة
settings-scheduler-empty = لا توجد عمليات فحص مجدولة بعد.
settings-scheduler-add = إضافة جدولة
settings-scheduler-frequency-daily = يوميًا
settings-scheduler-frequency-weekly = أسبوعيًا
settings-scheduler-frequency-monthly = شهريًا
settings-scheduler-frequency-oneshot = مرة واحدة
settings-scheduler-idle-only = لا تعمل إلا بعد { $seconds } ثانية من الخمول
settings-scheduler-disabled = مُعطّلة
