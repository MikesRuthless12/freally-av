# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Скасувати
button-confirm = Підтвердити
button-save = Зберегти
button-close = Закрити
button-scan-now = Сканувати зараз
button-pause = Призупинити
button-resume = Відновити
button-stop = Зупинити
button-retry = Повторити
button-export-bundle = Експортувати діагностичний пакет

## Navigation

nav-scan = Сканування
nav-history = Історія
nav-quarantine = Карантин
nav-exclusions = Винятки
nav-realtime = У реальному часі
nav-usb-devices = USB-пристрої
nav-settings = Налаштування

## Scan page

scan-title = Сканування
scan-status-idle = Очікування
scan-status-running = Сканування…
scan-status-paused = Призупинено
scan-status-cancelled = Скасовано
scan-status-completed = Завершено
scan-files-visited = Перевірено файлів: { $count }
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Загроз не виявлено
scan-findings-summary-one = 1 загроза
scan-findings-summary-other = Загроз виявлено: { $count }

## Real-time

realtime-mode-fsevents-observe = FSEvents (спостереження)
realtime-mode-fanotify-full = fanotify (повний)
realtime-mode-fanotify-observe = fanotify (спостереження)
realtime-mode-audit-fallback = резервний режим audit (лише спостереження)
realtime-mode-inotify-fallback = резервний режим inotify (лише спостереження)
realtime-shields-on = Захист у реальному часі: УВІМКНЕНО
realtime-shields-off = Захист у реальному часі: ВИМКНЕНО

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Діагностичний пакет
settings-about-bundle-help = Експортуйте zip із нещодавніми журналами рушія та вашою конфігурацією середовища. Шляхи сканування видаляються перед створенням пакета. Долучіть його до звіту про ваду в GitHub.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Заплановані сканування
settings-scheduler-empty = Запланованих сканувань ще немає.
settings-scheduler-add = Додати розклад
settings-scheduler-frequency-daily = Щодня
settings-scheduler-frequency-weekly = Щотижня
settings-scheduler-frequency-monthly = Щомісяця
settings-scheduler-frequency-oneshot = Одноразово
settings-scheduler-idle-only = Запускати лише після { $seconds } с бездіяльності
settings-scheduler-disabled = Вимкнено
