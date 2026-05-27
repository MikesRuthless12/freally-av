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

/// macOS process-table snapshot via `sysctl(KERN_PROC_ALL)`. The
/// returned map is `parent_pid → [child_pid]`. Empty when the
/// syscall fails (rare; corresponds to a permission error).
#[cfg(target_os = "macos")]
fn children_map() -> std::collections::HashMap<i32, Vec<i32>> {
    use std::collections::HashMap;
    // Two-phase sysctl call: first ask for the buffer size, then
    // allocate + ask for the data. The kernel guarantees the buffer
    // size is a multiple of `sizeof(struct kinfo_proc)` modulo a
    // small slack so we re-query until the call succeeds.
    let mut mib = [
        libc::CTL_KERN as i32,
        libc::KERN_PROC as i32,
        libc::KERN_PROC_ALL as i32,
        0,
    ];
    let mut size: libc::size_t = 0;
    // SAFETY: sysctl with a NULL output buffer is well-defined and
    // sets `size` to the required output length.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size == 0 {
        return HashMap::new();
    }
    // Pad by 25% to absorb growth between the two calls.
    let cap = size + size / 4;
    let mut buf: Vec<u8> = vec![0u8; cap];
    let mut got: libc::size_t = cap;
    // SAFETY: sysctl writes exactly `got` bytes into `buf`. We
    // re-bind `got` so the kernel can shrink it; we never read past
    // `got` below.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut got,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return HashMap::new();
    }
    let entry_size = std::mem::size_of::<libc::kinfo_proc>();
    if entry_size == 0 {
        return HashMap::new();
    }
    let count = got / entry_size;
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    // SAFETY: buf was just populated by sysctl with `got` bytes; we
    // walk it in `entry_size` strides, reading `count` `kinfo_proc`
    // entries. Each entry's `kp_proc.p_pid` + `kp_eproc.e_ppid` are
    // POD fields the kernel populates.
    let ptr = buf.as_ptr() as *const libc::kinfo_proc;
    for i in 0..count {
        let entry = unsafe { &*ptr.add(i) };
        let pid = entry.kp_proc.p_pid;
        let ppid = entry.kp_eproc.e_ppid;
        children.entry(ppid).or_default().push(pid);
    }
    children
}

/// Apply SIGSTOP to `pid` and every descendant. Best-effort — racing
/// process exits are silently dropped (errno ESRCH).
///
/// Implementation: walks the process table **once** via sysctl, then
/// BFS from `pid` through the resulting `parent → [child]` map.
/// Matches the Linux variant's O(N) shape so a process tree of any
/// depth is bounded.
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
        "SIGSTOP via sysctl(KERN_PROC_ALL) only available on macOS",
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
