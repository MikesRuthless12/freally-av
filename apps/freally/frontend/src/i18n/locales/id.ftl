# Freally Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Batal
button-confirm = Konfirmasi
button-save = Simpan
button-close = Tutup
button-scan-now = Pindai sekarang
button-pause = Jeda
button-resume = Lanjutkan
button-stop = Hentikan
button-retry = Coba lagi
button-export-bundle = Ekspor paket diagnostik

## Navigation

nav-scan = Pindai
nav-history = Riwayat
nav-quarantine = Karantina
nav-exclusions = Pengecualian
nav-realtime = Waktu nyata
nav-usb-devices = Perangkat USB
nav-settings = Pengaturan

## Scan page

scan-title = Pindai
scan-status-idle = Diam
scan-status-running = Memindai…
scan-status-paused = Dijeda
scan-status-cancelled = Dibatalkan
scan-status-completed = Selesai
scan-files-visited = { $count } berkas diperiksa
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Tidak ada temuan
scan-findings-summary-one = 1 temuan
scan-findings-summary-other = { $count } temuan

## Real-time

realtime-mode-fsevents-observe = FSEvents (observasi)
realtime-mode-fanotify-full = fanotify (penuh)
realtime-mode-fanotify-observe = fanotify (observasi)
realtime-mode-audit-fallback = cadangan audit (hanya observasi)
realtime-mode-inotify-fallback = cadangan inotify (hanya observasi)
realtime-shields-on = Perlindungan waktu nyata: AKTIF
realtime-shields-off = Perlindungan waktu nyata: NONAKTIF

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Paket diagnostik
settings-about-bundle-help = Ekspor berkas zip berisi log mesin terbaru dan konfigurasi runtime Anda. Jalur pemindaian dihapus sebelum paket ditulis. Lampirkan ke isu GitHub saat melaporkan bug.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Pemindaian terjadwal
settings-scheduler-empty = Belum ada pemindaian terjadwal.
settings-scheduler-add = Tambah jadwal
settings-scheduler-frequency-daily = Harian
settings-scheduler-frequency-weekly = Mingguan
settings-scheduler-frequency-monthly = Bulanan
settings-scheduler-frequency-oneshot = Sekali
settings-scheduler-idle-only = Hanya jalankan setelah { $seconds }d tidak aktif
settings-scheduler-disabled = Nonaktif

# More Freally apps (Central inside panel)
more-apps-menu = Aplikasi Freally lainnya
more-apps-title = Aplikasi Freally lainnya
