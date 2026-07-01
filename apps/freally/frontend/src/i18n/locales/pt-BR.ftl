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
button-save = Salvar
button-close = Fechar
button-scan-now = Verificar agora
button-pause = Pausar
button-resume = Retomar
button-stop = Parar
button-retry = Tentar novamente
button-export-bundle = Exportar pacote de diagnóstico

## Navigation

nav-scan = Verificação
nav-history = Histórico
nav-quarantine = Quarentena
nav-exclusions = Exclusões
nav-realtime = Tempo real
nav-usb-devices = Dispositivos USB
nav-settings = Configurações

## Scan page

scan-title = Verificação
scan-status-idle = Ocioso
scan-status-running = Verificando…
scan-status-paused = Pausado
scan-status-cancelled = Cancelado
scan-status-completed = Concluído
scan-files-visited = { $count } arquivos verificados
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Nenhuma detecção
scan-findings-summary-one = 1 detecção
scan-findings-summary-other = { $count } detecções

## Real-time

realtime-mode-fsevents-observe = FSEvents (observar)
realtime-mode-fanotify-full = fanotify (completo)
realtime-mode-fanotify-observe = fanotify (observar)
realtime-mode-audit-fallback = fallback de audit (somente observar)
realtime-mode-inotify-fallback = fallback de inotify (somente observar)
realtime-shields-on = Proteção em tempo real: ATIVADA
realtime-shields-off = Proteção em tempo real: DESATIVADA

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Pacote de diagnóstico
settings-about-bundle-help = Exporte um zip com os registros recentes do mecanismo e sua configuração de runtime. Os caminhos da verificação são removidos antes de o pacote ser gerado. Anexe a um issue do GitHub ao relatar um bug.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Verificações agendadas
settings-scheduler-empty = Nenhuma verificação agendada ainda.
settings-scheduler-add = Adicionar um agendamento
settings-scheduler-frequency-daily = Diariamente
settings-scheduler-frequency-weekly = Semanalmente
settings-scheduler-frequency-monthly = Mensalmente
settings-scheduler-frequency-oneshot = Uma vez
settings-scheduler-idle-only = Executar somente após { $seconds }s de inatividade
settings-scheduler-disabled = Desativado
