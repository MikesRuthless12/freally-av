//! Ransomware honeyfile tripwires — Linux daemon (TASK-142, FR-142).
//!
//! Builds on `freallykernel::detect::honeyfiles` (cross-platform planning
//! and write detection) by adding the Linux-specific **action**:
//! `kill(pid, SIGSTOP)` on the writer's whole process tree.
//!
//! Per § 1.5.4 the daemon never `SIGKILL`s — SIGSTOP suspends the
//! process group so the user can review and either resume / quarantine
//! / terminate from the UI.

use std::path::Path;

/// Apply SIGSTOP to `pid` and every descendant. Best-effort — racing
/// process exits are silently dropped (errno ESRCH).
///
/// Implementation: walks `/proc` **once** to build a `parent → [child]`
/// map, then BFS from `pid` through the map. The previous version
/// re-walked /proc per recursion level (O(N × D) reads) and lacked a
/// visited set, so a kernel-reported ppid cycle could stack-overflow.
#[cfg(target_os = "linux")]
pub fn sigstop_process_tree(pid: i32) -> std::io::Result<usize> {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::io::Read;
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Ok(0);
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(child_pid) = name.parse::<i32>() else {
            continue;
        };
        let mut buf = String::new();
        if std::fs::File::open(format!("/proc/{child_pid}/stat"))
            .and_then(|mut f| f.read_to_string(&mut buf))
            .is_err()
        {
            continue;
        }
        // `/proc/<pid>/stat` shape: `pid (comm) state ppid ...`.
        // `comm` may contain spaces but is parenthesized; the last
        // ')' is the close.
        let Some(close) = buf.rfind(')') else {
            continue;
        };
        let mut tail = buf[close + 1..].split_whitespace();
        let _state = tail.next();
        let Some(ppid_str) = tail.next() else {
            continue;
        };
        let Ok(ppid) = ppid_str.parse::<i32>() else {
            continue;
        };
        children.entry(ppid).or_default().push(child_pid);
    }
    let mut queue: VecDeque<i32> = VecDeque::new();
    let mut visited: HashSet<i32> = HashSet::new();
    queue.push_back(pid);
    let mut stopped = 0usize;
    while let Some(p) = queue.pop_front() {
        if !visited.insert(p) {
            continue;
        }
        // SAFETY: kill(2) with SIGSTOP is well-defined; non-existent
        // pids return ESRCH which we ignore.
        let rc = unsafe { libc::kill(p, libc::SIGSTOP) };
        if rc == 0 {
            stopped += 1;
        }
        if let Some(kids) = children.get(&p) {
            for k in kids {
                queue.push_back(*k);
            }
        }
    }
    Ok(stopped)
}

#[cfg(not(target_os = "linux"))]
pub fn sigstop_process_tree(_pid: i32) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SIGSTOP only available on Linux",
    ))
}

/// One canary-trip finding shape the daemon emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryTrip {
    pub canary_path: String,
    pub writer_pid: i32,
    pub writer_exe: String,
    pub stopped_pids: usize,
}

/// True when `write_event_path` matches the planned canary set.
/// Delegates to `freallykernel::detect::honeyfiles::is_canary_shape` for
/// the actual shape test; this thin wrapper documents the daemon
/// integration point.
pub fn is_canary_write(write_event_path: &Path) -> bool {
    freallykernel::detect::honeyfiles::is_canary_shape(write_event_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use freallykernel::detect::honeyfiles::plan_canaries;

    #[test]
    fn is_canary_write_matches_planned_paths() {
        let plan = plan_canaries(Path::new("/home/me"), 4, 1);
        for c in &plan {
            assert!(is_canary_write(&c.path));
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sigstop_off_linux_is_unsupported() {
        let err = sigstop_process_tree(1).unwrap_err();
        assert!(matches!(err.kind(), std::io::ErrorKind::Unsupported));
    }
}
