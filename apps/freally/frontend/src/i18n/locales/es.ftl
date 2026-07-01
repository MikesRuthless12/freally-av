# Freally Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Cancelar
button-confirm = Confirmar
button-save = Guardar
button-close = Cerrar
button-scan-now = Analizar ahora
button-pause = Pausar
button-resume = Reanudar
button-stop = Detener
button-retry = Reintentar
button-export-bundle = Exportar paquete de diagnóstico

## Navigation

nav-scan = Análisis
nav-history = Historial
nav-quarantine = Cuarentena
nav-exclusions = Exclusiones
nav-realtime = Tiempo real
nav-usb-devices = Dispositivos USB
nav-settings = Ajustes

## Scan page

scan-title = Análisis
scan-status-idle = Inactivo
scan-status-running = Analizando…
scan-status-paused = En pausa
scan-status-cancelled = Cancelado
scan-status-completed = Completado
scan-files-visited = { $count } archivos analizados
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Sin detecciones
scan-findings-summary-one = 1 detección
scan-findings-summary-other = { $count } detecciones

## Real-time

realtime-mode-fsevents-observe = FSEvents (observar)
realtime-mode-fanotify-full = fanotify (completo)
realtime-mode-fanotify-observe = fanotify (observar)
realtime-mode-audit-fallback = alternativa audit (solo observar)
realtime-mode-inotify-fallback = alternativa inotify (solo observar)
realtime-shields-on = Protección en tiempo real: ACTIVADA
realtime-shields-off = Protección en tiempo real: DESACTIVADA

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Paquete de diagnóstico
settings-about-bundle-help = Exporta un zip con los registros recientes del motor y tu configuración de ejecución. Las rutas de análisis se eliminan antes de generar el paquete. Adjúntalo a una incidencia de GitHub al informar de un error.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Análisis programados
settings-scheduler-empty = Aún no hay análisis programados.
settings-scheduler-add = Añadir una programación
settings-scheduler-frequency-daily = Diario
settings-scheduler-frequency-weekly = Semanal
settings-scheduler-frequency-monthly = Mensual
settings-scheduler-frequency-oneshot = Una vez
settings-scheduler-idle-only = Ejecutar solo tras { $seconds }s de inactividad
settings-scheduler-disabled = Desactivado
