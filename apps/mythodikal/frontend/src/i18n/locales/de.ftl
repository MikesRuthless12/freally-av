# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Abbrechen
button-confirm = Bestätigen
button-save = Speichern
button-close = Schließen
button-scan-now = Jetzt scannen
button-pause = Pausieren
button-resume = Fortsetzen
button-stop = Stoppen
button-retry = Wiederholen
button-export-bundle = Diagnosepaket exportieren

## Navigation

nav-scan = Scan
nav-history = Verlauf
nav-quarantine = Quarantäne
nav-exclusions = Ausnahmen
nav-realtime = Echtzeit
nav-usb-devices = USB-Geräte
nav-settings = Einstellungen

## Scan page

scan-title = Scan
scan-status-idle = Inaktiv
scan-status-running = Wird gescannt…
scan-status-paused = Pausiert
scan-status-cancelled = Abgebrochen
scan-status-completed = Abgeschlossen
scan-files-visited = { $count } Dateien geprüft
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Keine Funde
scan-findings-summary-one = 1 Fund
scan-findings-summary-other = { $count } Funde

## Real-time

realtime-mode-fsevents-observe = FSEvents (beobachten)
realtime-mode-fanotify-full = fanotify (vollständig)
realtime-mode-fanotify-observe = fanotify (beobachten)
realtime-mode-audit-fallback = audit-Fallback (nur beobachten)
realtime-mode-inotify-fallback = inotify-Fallback (nur beobachten)
realtime-shields-on = Echtzeitschutz: EIN
realtime-shields-off = Echtzeitschutz: AUS

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Diagnosepaket
settings-about-bundle-help = Exportieren Sie eine zip-Datei mit aktuellen Engine-Protokollen und Ihrer Laufzeitkonfiguration. Scan-Pfade werden vor dem Erstellen des Pakets entfernt. Hängen Sie sie an ein GitHub-Issue an, wenn Sie einen Fehler melden.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Geplante Scans
settings-scheduler-empty = Noch keine geplanten Scans.
settings-scheduler-add = Zeitplan hinzufügen
settings-scheduler-frequency-daily = Täglich
settings-scheduler-frequency-weekly = Wöchentlich
settings-scheduler-frequency-monthly = Monatlich
settings-scheduler-frequency-oneshot = Einmalig
settings-scheduler-idle-only = Nur nach { $seconds } s Inaktivität ausführen
settings-scheduler-disabled = Deaktiviert
