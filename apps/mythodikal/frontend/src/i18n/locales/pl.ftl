# Mythodikal Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Anuluj
button-confirm = Potwierdź
button-save = Zapisz
button-close = Zamknij
button-scan-now = Skanuj teraz
button-pause = Wstrzymaj
button-resume = Wznów
button-stop = Zatrzymaj
button-retry = Ponów
button-export-bundle = Eksportuj pakiet diagnostyczny

## Navigation

nav-scan = Skanowanie
nav-history = Historia
nav-quarantine = Kwarantanna
nav-exclusions = Wykluczenia
nav-realtime = Czas rzeczywisty
nav-usb-devices = Urządzenia USB
nav-settings = Ustawienia

## Scan page

scan-title = Skanowanie
scan-status-idle = Bezczynny
scan-status-running = Skanowanie…
scan-status-paused = Wstrzymano
scan-status-cancelled = Anulowano
scan-status-completed = Zakończono
scan-files-visited = Sprawdzone pliki: { $count }
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Brak wykryć
scan-findings-summary-one = 1 wykrycie
scan-findings-summary-other = Wykrycia: { $count }

## Real-time

realtime-mode-fsevents-observe = FSEvents (obserwacja)
realtime-mode-fanotify-full = fanotify (pełny)
realtime-mode-fanotify-observe = fanotify (obserwacja)
realtime-mode-audit-fallback = tryb awaryjny audit (tylko obserwacja)
realtime-mode-inotify-fallback = tryb awaryjny inotify (tylko obserwacja)
realtime-shields-on = Ochrona w czasie rzeczywistym: WŁ.
realtime-shields-off = Ochrona w czasie rzeczywistym: WYŁ.

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Pakiet diagnostyczny
settings-about-bundle-help = Wyeksportuj plik zip z najnowszymi dziennikami silnika i konfiguracją środowiska uruchomieniowego. Ścieżki skanowania są usuwane przed zapisaniem pakietu. Dołącz go do zgłoszenia w serwisie GitHub podczas raportowania błędu.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Zaplanowane skanowania
settings-scheduler-empty = Brak zaplanowanych skanowań.
settings-scheduler-add = Dodaj harmonogram
settings-scheduler-frequency-daily = Codziennie
settings-scheduler-frequency-weekly = Co tydzień
settings-scheduler-frequency-monthly = Co miesiąc
settings-scheduler-frequency-oneshot = Jednorazowo
settings-scheduler-idle-only = Uruchamiaj dopiero po { $seconds } s bezczynności
settings-scheduler-disabled = Wyłączone
