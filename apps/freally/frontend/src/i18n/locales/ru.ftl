# Freally Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Отмена
button-confirm = Подтвердить
button-save = Сохранить
button-close = Закрыть
button-scan-now = Сканировать
button-pause = Пауза
button-resume = Продолжить
button-stop = Остановить
button-retry = Повторить
button-export-bundle = Экспорт диагностического пакета

## Navigation

nav-scan = Сканирование
nav-history = История
nav-quarantine = Карантин
nav-exclusions = Исключения
nav-realtime = В реальном времени
nav-usb-devices = USB-устройства
nav-settings = Настройки

## Scan page

scan-title = Сканирование
scan-status-idle = Ожидание
scan-status-running = Сканирование…
scan-status-paused = Приостановлено
scan-status-cancelled = Отменено
scan-status-completed = Завершено
scan-files-visited = Проверено файлов: { $count }
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Угроз не найдено
scan-findings-summary-one = Найдена 1 угроза
scan-findings-summary-other = Найдено угроз: { $count }

## Real-time

realtime-mode-fsevents-observe = FSEvents (наблюдение)
realtime-mode-fanotify-full = fanotify (полный)
realtime-mode-fanotify-observe = fanotify (наблюдение)
realtime-mode-audit-fallback = резервный режим audit (только наблюдение)
realtime-mode-inotify-fallback = резервный режим inotify (только наблюдение)
realtime-shields-on = Защита в реальном времени: ВКЛ
realtime-shields-off = Защита в реальном времени: ВЫКЛ

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Диагностический пакет
settings-about-bundle-help = Экспорт zip-архива с последними журналами движка и вашей конфигурацией среды. Пути сканирования удаляются перед созданием пакета. Прикрепите его к issue на GitHub при сообщении об ошибке.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Запланированные сканирования
settings-scheduler-empty = Запланированных сканирований пока нет.
settings-scheduler-add = Добавить расписание
settings-scheduler-frequency-daily = Ежедневно
settings-scheduler-frequency-weekly = Еженедельно
settings-scheduler-frequency-monthly = Ежемесячно
settings-scheduler-frequency-oneshot = Однократно
settings-scheduler-idle-only = Запускать только после { $seconds } с простоя
settings-scheduler-disabled = Отключено

# More Freally apps (Central inside panel)
more-apps-menu = Другие приложения Freally
more-apps-title = Другие приложения Freally
