# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = İptal
button-confirm = Onayla
button-save = Kaydet
button-close = Kapat
button-scan-now = Şimdi tara
button-pause = Duraklat
button-resume = Sürdür
button-stop = Durdur
button-retry = Yeniden dene
button-export-bundle = Tanılama paketini dışa aktar

## Navigation

nav-scan = Tarama
nav-history = Geçmiş
nav-quarantine = Karantina
nav-exclusions = Hariç tutulanlar
nav-realtime = Gerçek zamanlı
nav-usb-devices = USB aygıtları
nav-settings = Ayarlar

## Scan page

scan-title = Tarama
scan-status-idle = Boşta
scan-status-running = Taranıyor…
scan-status-paused = Duraklatıldı
scan-status-cancelled = İptal edildi
scan-status-completed = Tamamlandı
scan-files-visited = { $count } dosya tarandı
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Bulgu yok
scan-findings-summary-one = 1 bulgu
scan-findings-summary-other = { $count } bulgu

## Real-time

realtime-mode-fsevents-observe = FSEvents (gözlemleme)
realtime-mode-fanotify-full = fanotify (tam)
realtime-mode-fanotify-observe = fanotify (gözlemleme)
realtime-mode-audit-fallback = audit yedeği (yalnızca gözlemleme)
realtime-mode-inotify-fallback = inotify yedeği (yalnızca gözlemleme)
realtime-shields-on = Gerçek zamanlı koruma: AÇIK
realtime-shields-off = Gerçek zamanlı koruma: KAPALI

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Tanılama paketi
settings-about-bundle-help = Son motor günlüklerini ve çalışma zamanı yapılandırmanızı içeren bir zip dışa aktarın. Tarama yolları, paket yazılmadan önce kaldırılır. Bir hata bildirirken GitHub sorununa ekleyin.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Zamanlanmış taramalar
settings-scheduler-empty = Henüz zamanlanmış tarama yok.
settings-scheduler-add = Zamanlama ekle
settings-scheduler-frequency-daily = Günlük
settings-scheduler-frequency-weekly = Haftalık
settings-scheduler-frequency-monthly = Aylık
settings-scheduler-frequency-oneshot = Bir kez
settings-scheduler-idle-only = Yalnızca { $seconds } sn boşta kaldıktan sonra çalıştır
settings-scheduler-disabled = Devre dışı
