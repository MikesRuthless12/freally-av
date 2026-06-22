# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Annuleren
button-confirm = Bevestigen
button-save = Opslaan
button-close = Sluiten
button-scan-now = Nu scannen
button-pause = Pauzeren
button-resume = Hervatten
button-stop = Stoppen
button-retry = Opnieuw proberen
button-export-bundle = Diagnostische bundel exporteren

## Navigation

nav-scan = Scannen
nav-history = Geschiedenis
nav-quarantine = Quarantaine
nav-exclusions = Uitsluitingen
nav-realtime = Realtime
nav-usb-devices = USB-apparaten
nav-settings = Instellingen

## Scan page

scan-title = Scannen
scan-status-idle = Inactief
scan-status-running = Bezig met scannen…
scan-status-paused = Gepauzeerd
scan-status-cancelled = Geannuleerd
scan-status-completed = Voltooid
scan-files-visited = { $count } bestanden gecontroleerd
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Geen bevindingen
scan-findings-summary-one = 1 bevinding
scan-findings-summary-other = { $count } bevindingen

## Real-time

realtime-mode-fsevents-observe = FSEvents (observeren)
realtime-mode-fanotify-full = fanotify (volledig)
realtime-mode-fanotify-observe = fanotify (observeren)
realtime-mode-audit-fallback = audit-terugval (alleen observeren)
realtime-mode-inotify-fallback = inotify-terugval (alleen observeren)
realtime-shields-on = Realtimebeveiliging: AAN
realtime-shields-off = Realtimebeveiliging: UIT

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Diagnostische bundel
settings-about-bundle-help = Exporteer een zip met recente engine-logboeken en uw runtimeconfiguratie. Scanpaden worden verwijderd voordat de bundel wordt weggeschreven. Voeg deze toe aan een GitHub-issue wanneer u een bug meldt.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Geplande scans
settings-scheduler-empty = Nog geen geplande scans.
settings-scheduler-add = Een planning toevoegen
settings-scheduler-frequency-daily = Dagelijks
settings-scheduler-frequency-weekly = Wekelijks
settings-scheduler-frequency-monthly = Maandelijks
settings-scheduler-frequency-oneshot = Eenmalig
settings-scheduler-idle-only = Alleen uitvoeren na { $seconds }s inactiviteit
settings-scheduler-disabled = Uitgeschakeld
