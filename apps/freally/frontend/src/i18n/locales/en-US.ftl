# Freally Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Cancel
button-confirm = Confirm
button-save = Save
button-close = Close
button-scan-now = Scan now
button-pause = Pause
button-resume = Resume
button-stop = Stop
button-retry = Retry
button-export-bundle = Export diagnostic bundle

## Navigation

nav-scan = Scan
nav-history = History
nav-quarantine = Quarantine
nav-exclusions = Exclusions
nav-realtime = Real-time
nav-usb-devices = USB devices
nav-settings = Settings

## Scan page

scan-title = Scan
scan-status-idle = Idle
scan-status-running = Scanning…
scan-status-paused = Paused
scan-status-cancelled = Cancelled
scan-status-completed = Completed
scan-files-visited = { $count } files visited
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = No findings
scan-findings-summary-one = 1 finding
scan-findings-summary-other = { $count } findings

## Real-time

realtime-mode-fsevents-observe = FSEvents (observe)
realtime-mode-fanotify-full = fanotify (full)
realtime-mode-fanotify-observe = fanotify (observe)
realtime-mode-audit-fallback = audit fallback (observe only)
realtime-mode-inotify-fallback = inotify fallback (observe only)
realtime-shields-on = Real-time protection: ON
realtime-shields-off = Real-time protection: OFF

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Diagnostic bundle
settings-about-bundle-help = Export a zip with recent engine logs and your runtime config. Scan paths are stripped before the bundle is written. Attach to a GitHub issue when reporting a bug.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Scheduled scans
settings-scheduler-empty = No scheduled scans yet.
settings-scheduler-add = Add a schedule
settings-scheduler-frequency-daily = Daily
settings-scheduler-frequency-weekly = Weekly
settings-scheduler-frequency-monthly = Monthly
settings-scheduler-frequency-oneshot = Once
settings-scheduler-idle-only = Only run after { $seconds }s of idle
settings-scheduler-disabled = Disabled
