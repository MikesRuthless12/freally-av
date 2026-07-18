# Freally Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Annulla
button-confirm = Conferma
button-save = Salva
button-close = Chiudi
button-scan-now = Scansiona ora
button-pause = Sospendi
button-resume = Riprendi
button-stop = Interrompi
button-retry = Riprova
button-export-bundle = Esporta pacchetto diagnostico

## Navigation

nav-scan = Scansione
nav-history = Cronologia
nav-quarantine = Quarantena
nav-exclusions = Esclusioni
nav-realtime = Tempo reale
nav-usb-devices = Dispositivi USB
nav-settings = Impostazioni

## Scan page

scan-title = Scansione
scan-status-idle = Inattivo
scan-status-running = Scansione in corso…
scan-status-paused = In pausa
scan-status-cancelled = Annullata
scan-status-completed = Completata
scan-files-visited = { $count } file analizzati
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Nessun rilevamento
scan-findings-summary-one = 1 rilevamento
scan-findings-summary-other = { $count } rilevamenti

## Real-time

realtime-mode-fsevents-observe = FSEvents (osservazione)
realtime-mode-fanotify-full = fanotify (completo)
realtime-mode-fanotify-observe = fanotify (osservazione)
realtime-mode-audit-fallback = ripiego audit (solo osservazione)
realtime-mode-inotify-fallback = ripiego inotify (solo osservazione)
realtime-shields-on = Protezione in tempo reale: ATTIVA
realtime-shields-off = Protezione in tempo reale: DISATTIVATA

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Pacchetto diagnostico
settings-about-bundle-help = Esporta uno zip con i log recenti del motore e la configurazione di runtime. I percorsi di scansione vengono rimossi prima della creazione del pacchetto. Allegalo a una issue su GitHub quando segnali un bug.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Scansioni pianificate
settings-scheduler-empty = Nessuna scansione pianificata.
settings-scheduler-add = Aggiungi una pianificazione
settings-scheduler-frequency-daily = Giornaliera
settings-scheduler-frequency-weekly = Settimanale
settings-scheduler-frequency-monthly = Mensile
settings-scheduler-frequency-oneshot = Una volta
settings-scheduler-idle-only = Esegui solo dopo { $seconds }s di inattività
settings-scheduler-disabled = Disattivata

# More Freally apps (Central inside panel)
more-apps-menu = Altre app Freally
more-apps-title = Altre app Freally
