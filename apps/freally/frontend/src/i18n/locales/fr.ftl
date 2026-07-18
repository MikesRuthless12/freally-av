# Freally Anti-Virus — English (US) localisation file (TASK-089).
#
# Fluent syntax — https://projectfluent.org/. This is the seed file
# every other locale forks from. Add new strings in lexical order under
# the section that matches the UI surface; never delete a key that's
# still referenced from a Tsx component (Fluent falls back to the key
# itself when a locale lacks an entry, which makes "missing" obvious in
# the UI rather than silent).

## Common buttons

button-cancel = Annuler
button-confirm = Confirmer
button-save = Enregistrer
button-close = Fermer
button-scan-now = Analyser maintenant
button-pause = Suspendre
button-resume = Reprendre
button-stop = Arrêter
button-retry = Réessayer
button-export-bundle = Exporter le lot de diagnostic

## Navigation

nav-scan = Analyse
nav-history = Historique
nav-quarantine = Quarantaine
nav-exclusions = Exclusions
nav-realtime = Temps réel
nav-usb-devices = Périphériques USB
nav-settings = Paramètres

## Scan page

scan-title = Analyse
scan-status-idle = Inactif
scan-status-running = Analyse en cours…
scan-status-paused = Suspendue
scan-status-cancelled = Annulée
scan-status-completed = Terminée
scan-files-visited = { $count } fichiers analysés
# Plural forms are expressed as separate keys (the scaffolding parser
# does not implement Fluent's selector grammar — see src/i18n/index.tsx
# header). Component picks the right key based on the count.
scan-findings-summary-zero = Aucune détection
scan-findings-summary-one = 1 détection
scan-findings-summary-other = { $count } détections

## Real-time

realtime-mode-fsevents-observe = FSEvents (observation)
realtime-mode-fanotify-full = fanotify (complet)
realtime-mode-fanotify-observe = fanotify (observation)
realtime-mode-audit-fallback = repli audit (observation uniquement)
realtime-mode-inotify-fallback = repli inotify (observation uniquement)
realtime-shields-on = Protection en temps réel : ACTIVÉE
realtime-shields-off = Protection en temps réel : DÉSACTIVÉE

## Settings — diagnostics (TASK-088)

settings-about-bundle-title = Lot de diagnostic
settings-about-bundle-help = Exportez un fichier zip contenant les journaux récents du moteur et votre configuration d'exécution. Les chemins d'analyse sont supprimés avant l'écriture du lot. Joignez-le à un ticket GitHub lors du signalement d'un bogue.

## Settings — scheduler (TASK-086)

settings-scheduler-title = Analyses planifiées
settings-scheduler-empty = Aucune analyse planifiée pour le moment.
settings-scheduler-add = Ajouter une planification
settings-scheduler-frequency-daily = Quotidienne
settings-scheduler-frequency-weekly = Hebdomadaire
settings-scheduler-frequency-monthly = Mensuelle
settings-scheduler-frequency-oneshot = Une fois
settings-scheduler-idle-only = Exécuter uniquement après { $seconds } s d'inactivité
settings-scheduler-disabled = Désactivée

# More Freally apps (Central inside panel)
more-apps-menu = Plus d'apps Freally
more-apps-title = Plus d'apps Freally
