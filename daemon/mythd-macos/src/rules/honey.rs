//! Ransomware honeyfile tripwires — macOS daemon (TASK-161, FR-142,
//! Phase 9 Wave 1).
//!
//! Builds on `mythkernel::detect::honeyfiles` (cross-platform planning
//! and write detection) by adding the macOS-specific **action**:
//! `kill(pid, SIGSTOP)` on the writer's whole process tree. The
//! Linux variant lives at `daemon/mythd-linux/src/rules/honey.rs`
//! (TASK-142); both surfaces share the planner module.
//!
//! Per `docs/prd.md` § 1.5.4 the daemon never `SIGKILL`s — SIGSTOP
//! suspends the process group so the user can review and either
//! resume / quarantine / terminate from the UI. SIGSTOP also works
//! NOTIFY-only: it's a post-event action (we observed the write,
//! THEN suspended the writer), not a pre-syscall AUTH veto.

use std::path::Path;

/// macOS process-table snapshot via `proc_listpids` + `proc_pidinfo`
/// (Apple's `<libproc.h>` API — the modern replacement for the
/// `sysctl(KERN_PROC_ALL)` + `kinfo_proc` path which `libc` no longer
/// exposes as of 0.2.186). The returned map is
/// `parent_pid → [child_pid]`. Empty when either syscall fails.
#[cfg(target_os = "macos")]
fn children_map() -> std::collections::HashMap<i32, Vec<i32>> {
    use std::collections::HashMap;

    // Apple's `<libproc.h>` constant — not yet exposed by `libc`.
    const PROC_ALL_PIDS: u32 = 1;

    // Phase 1 — ask the kernel how many bytes of PIDs it has.
    // SAFETY: `proc_listpids` with `buffer == NULL` and `buffersize == 0`
    // is well-defined per `<libproc.h>` — returns the buffer size needed.
    let size_needed = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if size_needed <= 0 {
        return HashMap::new();
    }

    // Pad by 25% to absorb growth between calls.
    let cap_bytes = (size_needed as usize) + (size_needed as usize) / 4;
    let pid_size = std::mem::size_of::<i32>();
    let cap_pids = cap_bytes.div_ceil(pid_size);
    let mut pids: Vec<i32> = vec![0; cap_pids];

    // Phase 2 — fill the buffer. Returns the number of bytes actually
    // written; we re-derive the entry count from that.
    // SAFETY: buffer is `cap_pids * pid_size` bytes; `buffersize` argument
    // matches that exactly; output is i32 PIDs.
    let got_bytes = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr() as *mut libc::c_void,
            (pids.len() * pid_size) as i32,
        )
    };
    if got_bytes <= 0 {
        return HashMap::new();
    }
    let count = (got_bytes as usize) / pid_size;

    // Phase 3 — per-PID parent lookup via `proc_pidinfo(PROC_PIDTBSDINFO)`.
    // `proc_bsdinfo::pbi_ppid` gives us the parent. Best-effort: a
    // process that exits between Phase 2 and Phase 3 returns
    // `got_info != bsd_size`; we drop those rows rather than fail.
    let bsd_size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for &pid in pids.iter().take(count) {
        if pid <= 0 {
            continue; // pid 0 is the kernel; skip
        }
        // SAFETY: `proc_bsdinfo` is `#[repr(C)]` POD; zeroing it is a
        // valid initial state. `proc_pidinfo` writes `bsd_size` bytes
        // into it on success.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let got_info = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                bsd_size,
            )
        };
        if got_info != bsd_size {
            continue;
        }
        let ppid = info.pbi_ppid as i32;
        children.entry(ppid).or_default().push(pid);
    }
    children
}

/// Apply SIGSTOP to `pid` and every descendant. Best-effort — racing
/// process exits are silently dropped (errno ESRCH).
///
/// Implementation: walks the process table **once** via
/// `proc_listpids` + `proc_pidinfo` (`<libproc.h>`), then BFS from
/// `pid` through the resulting `parent → [child]` map. Matches the
/// Linux variant's O(N) shape so a process tree of any depth is
/// bounded.
#[cfg(target_os = "macos")]
pub fn sigstop_process_tree(pid: i32) -> std::io::Result<usize> {
    use std::collections::{HashSet, VecDeque};
    let children = children_map();
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

#[cfg(not(target_os = "macos"))]
pub fn sigstop_process_tree(_pid: i32) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SIGSTOP via proc_listpids only available on macOS",
    ))
}

/// One canary-trip finding shape the daemon emits. Mirrors the Linux
/// variant so the engine's finding handler is platform-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryTrip {
    pub canary_path: String,
    pub writer_pid: i32,
    pub writer_exe: String,
    pub stopped_pids: usize,
}

/// True when `write_event_path` matches the planned canary set.
/// Delegates to `mythkernel::detect::honeyfiles::is_canary_shape` for
/// the actual shape test; this thin wrapper documents the daemon
/// integration point.
pub fn is_canary_write(write_event_path: &Path) -> bool {
    mythkernel::detect::honeyfiles::is_canary_shape(write_event_path)
}

/// The user-document roots the macOS daemon plants canaries under,
/// per the PRD. Caller passes in the home directory because the
/// daemon may be running for a different `HOME` than the engine's
/// `~` (e.g. invoked from a launchd LaunchAgent during a user
/// switch).
pub fn default_canary_roots(home: &Path) -> Vec<std::path::PathBuf> {
    vec![
        home.join("Documents"),
        home.join("Desktop"),
        home.join("Pictures"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use mythkernel::detect::honeyfiles::plan_canaries;

    #[test]
    fn is_canary_write_matches_planned_paths() {
        let plan = plan_canaries(Path::new("/Users/me"), 4, 1);
        for c in &plan {
            assert!(is_canary_write(&c.path));
        }
    }

    #[test]
    fn default_canary_roots_covers_three_mac_doc_trees() {
        let roots = default_canary_roots(Path::new("/Users/me"));
        let names: Vec<String> = roots
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "Documents".to_string(),
                "Desktop".to_string(),
                "Pictures".to_string()
            ]
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn sigstop_off_macos_is_unsupported() {
        let err = sigstop_process_tree(1).unwrap_err();
        assert!(matches!(err.kind(), std::io::ErrorKind::Unsupported));
    }
}
