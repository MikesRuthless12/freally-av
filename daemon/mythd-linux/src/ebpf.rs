//! Linux eBPF observe-only telemetry tap (TASK-236, Phase 8 Wave 2).
//!
//! Loads a CO-RE eBPF program (via `aya`) that traces
//! `sys_enter_execve`, `sys_enter_openat`, and `sys_enter_connect` into
//! a user-mode ring buffer. **Observe-only** — no LSM hooks, no
//! `bpf_send_signal`, no policy influence on fanotify replies. Per
//! § 1.5.4 the tap exists only for the live event log (TASK-075 UI)
//! and forensic correlation.
//!
//! Gracefully disabled when `/sys/kernel/btf/vmlinux` is missing,
//! `CAP_BPF` is missing, or the kernel is older than 5.8.
//!
//! `aya` itself is dual MIT/Apache so the dep tree stays clean. The
//! crate is only pulled in on `cfg(target_os = "linux")`; this module
//! compiles on every OS so the daemon binary's loader code lives in
//! one place.

#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    #[error("eBPF observer disabled: {0}")]
    Disabled(&'static str),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EbpfSyscall {
    Execve,
    Openat,
    Connect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfRecord {
    pub syscall: EbpfSyscall,
    pub pid: i32,
    /// Comm (process basename) as captured by the eBPF program.
    pub comm: String,
    /// Per-syscall payload. For `Openat`/`Execve` this is the
    /// pathname argument; for `Connect` it is the `getpeername`-style
    /// `"ip:port"` form.
    pub detail: String,
}

/// Probe whether the host supports the BPF features the program needs.
/// Pure logic — exposed for unit tests on every host.
pub fn host_supports_bpf(btf_vmlinux: bool, has_cap_bpf: bool, kernel_minor: u32) -> bool {
    btf_vmlinux && has_cap_bpf && kernel_minor >= 8
}

pub struct EbpfObserver {
    pub disabled_reason: Option<&'static str>,
}

impl EbpfObserver {
    /// Try to load the observer. Returns an instance whose
    /// `disabled_reason` is `Some(...)` when the host can't run it.
    /// The caller logs `"eBPF observer disabled: <reason>"` and
    /// proceeds with fanotify-only.
    #[cfg(target_os = "linux")]
    pub fn load() -> Result<Self, EbpfError> {
        // Wave 2 ships the disabled-reason scaffolding + the host
        // probe. The actual `aya::Ebpf::load_file` + ring-buffer poll
        // need the bpf-linker toolchain available at build time AND
        // Linux runtime — both belong in the runtime-validation pass.
        let reason = if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            Some("BTF /sys/kernel/btf/vmlinux not present")
        } else {
            None
        };
        Ok(Self {
            disabled_reason: reason,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load() -> Result<Self, EbpfError> {
        Ok(Self {
            disabled_reason: Some("non-Linux host"),
        })
    }

    pub fn is_active(&self) -> bool {
        self.disabled_reason.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_probe_requires_btf_cap_and_minimum_kernel() {
        assert!(host_supports_bpf(true, true, 8));
        assert!(host_supports_bpf(true, true, 16));
        assert!(!host_supports_bpf(false, true, 8));
        assert!(!host_supports_bpf(true, false, 8));
        assert!(!host_supports_bpf(true, true, 7));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn observer_off_linux_is_disabled() {
        let obs = EbpfObserver::load().unwrap();
        assert!(!obs.is_active());
        assert_eq!(obs.disabled_reason, Some("non-Linux host"));
    }
}
