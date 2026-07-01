//! `audit` subsystem fanotify fallback (TASK-237, Phase 8 Wave 2).
//!
//! When `fanotify_init` rejects `FAN_MARK_FILESYSTEM` on a kernel
//! that's too old for whole-FS marks (configurable via
//! `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`), the daemon falls back to
//! consuming `/var/log/audit/audit.log` via netlink-AUDIT subscribes.
//! Observe-only — the UI shows "audit (observe-only)" and disables
//! the "block-on-detect" toggle.
//!
//! Audit rules installed by the daemon are tagged with `key=freally`
//! so the daemon's `--uninstall` path can remove only its own rules.

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit netlink not supported on this host (not a Linux target)")]
    Unsupported,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("netlink error: {0}")]
    Netlink(String),
}

/// One parsed audit record. The audit subsystem emits multi-line
/// records keyed by `audit(NNNN.NNN:N)` ids; we join the `SYSCALL`
/// and `PATH` records by id into one normalized event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub audit_id: String,
    pub syscall_name: String,
    pub pid: i32,
    pub path: String,
}

/// Partially-assembled record keyed by `audit(...)` id while the parser
/// is consuming the multi-line audit block. The `Option`s reflect that
/// the SYSCALL and PATH lines arrive separately and either may be
/// absent (a SYSCALL with no PATH still produces an event; a PATH with
/// no SYSCALL is dropped).
#[derive(Default)]
struct PartialAuditRecord {
    syscall_and_pid: Option<(String, i32)>,
    path: Option<String>,
}

/// Pure parser — joins SYSCALL + PATH records by `audit(...)` id.
/// Lives in this module (not behind a Linux cfg-gate) because it's
/// pure string-munging and is exercised by unit tests on every host.
pub fn parse_audit_block(text: &str) -> Vec<AuditEvent> {
    use std::collections::BTreeMap;
    let mut by_id: BTreeMap<String, PartialAuditRecord> = BTreeMap::new();
    for line in text.lines() {
        let Some(audit_id) = extract_audit_id(line) else {
            continue;
        };
        let entry = by_id.entry(audit_id).or_default();
        if line.contains("type=SYSCALL") {
            entry.syscall_and_pid = Some((
                extract_kv(line, "syscall=").unwrap_or_default(),
                extract_kv(line, "pid=")
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0),
            ));
        } else if line.contains("type=PATH") {
            // PATH records ship `name="..."`; trim the quotes.
            if let Some(name) = extract_kv(line, "name=") {
                entry.path = Some(name.trim_matches('"').to_string());
            }
        }
    }
    by_id
        .into_iter()
        .filter_map(|(id, rec)| {
            let (syscall_name, pid) = rec.syscall_and_pid?;
            Some(AuditEvent {
                audit_id: id,
                syscall_name,
                pid,
                path: rec.path.unwrap_or_default(),
            })
        })
        .collect()
}

fn extract_audit_id(line: &str) -> Option<String> {
    // shape: ... audit(1700000000.123:42): ...
    let start = line.find("audit(")? + "audit(".len();
    let end = line[start..].find(')')?;
    Some(line[start..start + end].to_string())
}

/// Substring-extract `key=<value>` from an audit line. Match is
/// **word-boundary**: the byte before `key` must be the start of the
/// line or whitespace. Without this guard, `extract_kv(line, "pid=")`
/// would match the trailing `pid=` inside `ppid=`, returning the
/// parent PID instead of the syscall PID and corrupting every
/// audit-mode event with the wrong process id.
fn extract_kv(line: &str, key: &str) -> Option<String> {
    let mut search_from = 0usize;
    while let Some(rel) = line[search_from..].find(key) {
        let abs = search_from + rel;
        let preceded_by_boundary =
            abs == 0 || line.as_bytes()[abs - 1] == b' ' || line.as_bytes()[abs - 1] == b'\t';
        if preceded_by_boundary {
            let rest = &line[abs + key.len()..];
            let end = rest.find([' ', '\n']).unwrap_or(rest.len());
            return Some(rest[..end].to_string());
        }
        search_from = abs + key.len();
    }
    None
}

pub struct AuditHandle {
    pub mode_label: String,
}

impl AuditHandle {
    #[cfg(target_os = "linux")]
    pub fn open() -> Result<Self, AuditError> {
        // Wave 2 ships the parser + the mode contract. The actual
        // NETLINK_AUDIT socket open + rule install need Linux runtime
        // (and elevated privileges) and land in the runtime
        // validation pass.
        Ok(Self {
            mode_label: "audit (observe-only)".to_string(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open() -> Result<Self, AuditError> {
        Err(AuditError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "type=SYSCALL msg=audit(1700000000.123:42): syscall=openat pid=1234 success=yes\n\
                          type=PATH msg=audit(1700000000.123:42): name=\"/etc/hostname\" inode=4096\n";

    #[test]
    fn joins_syscall_and_path_records_by_id() {
        let events = parse_audit_block(SAMPLE);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.audit_id, "1700000000.123:42");
        assert_eq!(ev.syscall_name, "openat");
        assert_eq!(ev.pid, 1234);
        assert_eq!(ev.path, "/etc/hostname");
    }

    #[test]
    fn extract_kv_does_not_match_ppid_when_looking_for_pid() {
        // Real audit records have BOTH `ppid=` and `pid=` on the same
        // line; without word-boundary matching the parser used to
        // return the parent PID for every event.
        let line = "type=SYSCALL msg=audit(1.0:1): syscall=openat ppid=1000 pid=1234 success=yes";
        assert_eq!(extract_kv(line, "pid=").as_deref(), Some("1234"));
        assert_eq!(extract_kv(line, "ppid=").as_deref(), Some("1000"));
    }

    #[test]
    fn unrelated_lines_are_ignored() {
        let mixed = format!("kernel boot message\n{SAMPLE}some other log line\n");
        let events = parse_audit_block(&mixed);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn missing_syscall_record_drops_event() {
        let path_only = "type=PATH msg=audit(1.0:1): name=\"/etc/passwd\"";
        assert!(parse_audit_block(path_only).is_empty());
    }
}
