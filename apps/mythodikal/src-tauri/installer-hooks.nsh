; NSIS uninstaller hooks (Phase 5 wave 3 follow-up — task #24).
;
; Problem fixed by this file: the default NSIS uninstaller deletes
; files via `Delete` but doesn't kill the running process first. If
; mythodikal-app.exe is currently running (likely — the user usually
; uninstalls AV apps while the app is open in the tray), the Delete
; calls silently fail and the EXE plus install dir stay behind. The
; user is left with a stale C:\Program Files\Mythodikal Anti-Virus\
; that the next install detects as a downgrade and refuses to
; overwrite.
;
; What this hook does:
;   1. NSIS_HOOK_PREUNINSTALL: kill the app + scheduler + tray
;      threads before any Delete call fires.
;   2. NSIS_HOOK_POSTUNINSTALL: force-remove the install dir tree
;      even if a stray file slipped through, then SetRebootFlag if
;      anything still couldn't be removed (rare — typically only
;      happens when a file handle survives our taskkill).

!macro NSIS_HOOK_PREUNINSTALL
    DetailPrint "Stopping Mythodikal Anti-Virus processes..."
    ; /F = force, /T = also kill child processes (the scheduler
    ; runtime thread + tray handler), /IM = by image name.
    nsExec::Exec 'taskkill /F /T /IM mythodikal-app.exe'
    Pop $0
    ; Brief settle delay so Windows fully releases the file handles
    ; before the Delete pass runs.
    Sleep 500
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
    DetailPrint "Cleaning up install directory..."
    ; Recursive force-remove of the install root. RMDir /R /REBOOTOK
    ; queues a reboot-time delete for any file that's still locked
    ; (typically because antivirus / search indexer is holding a
    ; handle — that's the user's third-party AV, not us).
    RMDir /r /REBOOTOK "$INSTDIR"
!macroend
