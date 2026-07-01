# Linux packaging

This directory ships the systemd unit + .deb / .rpm install scripts
for `freallyd-linux` (TASK-073 / TASK-076, Phase 8).

| File             | Purpose                                                 |
| ---------------- | ------------------------------------------------------- |
| `freallyd.service`  | systemd unit. Installed to `/lib/systemd/system/`.      |
| `postinst`       | Enables + starts the daemon on .deb / .rpm install.     |
| `prerm`          | Stops + disables the daemon on uninstall.               |

Distinction from FR-161 / TASK-157 (user-app autostart): these scripts
manage the **kernel-privilege daemon** lifecycle. The user-mode UI
app's start-at-login is governed by `tauri-plugin-autostart` and is
independent.

Per `docs/prd.md` § 1.5.4: no kernel module load. The daemon is
user-mode and depends only on `CAP_SYS_ADMIN` for the fanotify FD.
