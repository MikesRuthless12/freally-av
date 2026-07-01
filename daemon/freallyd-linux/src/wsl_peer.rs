//! WSL-side peer tagger (TASK-240, Phase 8 Wave 2).
//!
//! When the Linux daemon runs **inside a WSL2 distro**, every emitted
//! event is tagged with `WSL_DISTRO_NAME` so the Windows-side daemon
//! (`freallyd-windows`, TASK-240 host side) can attribute the event to
//! the right distro in the unified UI panel.
//!
//! Pure detection logic — checks `/proc/sys/kernel/osrelease` for
//! the `"microsoft"` substring and reads the `WSL_DISTRO_NAME` env
//! var. The actual cross-host transport (vsock or
//! `\\wsl.localhost\<distro>\run\freallyd\freallyd.sock`) is owned by
//! `daemon/freallyd-windows/src/wsl_bridge.rs`.
//!
//! The shared `wsl.exe --list --verbose` parser lives in
//! `freallykernel::platform::wsl` and is re-exported here so callers can
//! pull the whole WSL surface from one module.

pub use freallykernel::platform::wsl::{WslDistroRow, parse_wsl_list_text, parse_wsl_list_utf16le};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslContext {
    /// `WSL_DISTRO_NAME` env var, e.g. "Ubuntu" or "Debian".
    pub distro_name: Option<String>,
    /// True when `/proc/sys/kernel/osrelease` contains "microsoft".
    pub in_wsl: bool,
}

impl WslContext {
    pub fn detect() -> Self {
        let in_wsl = read_osrelease()
            .map(|s| s.to_lowercase().contains("microsoft"))
            .unwrap_or(false);
        let distro_name = std::env::var("WSL_DISTRO_NAME")
            .ok()
            .filter(|s| !s.trim().is_empty());
        Self {
            distro_name,
            in_wsl,
        }
    }

    /// Returns a tag string the daemon staples onto every emitted
    /// event ("wsl:Ubuntu") or `None` when the daemon is running on
    /// bare Linux.
    pub fn event_tag(&self) -> Option<String> {
        if !self.in_wsl {
            return None;
        }
        Some(match &self.distro_name {
            Some(d) => format!("wsl:{d}"),
            None => "wsl:unknown".to_string(),
        })
    }
}

fn read_osrelease() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_tag_includes_distro_when_in_wsl() {
        let ctx = WslContext {
            distro_name: Some("Ubuntu".into()),
            in_wsl: true,
        };
        assert_eq!(ctx.event_tag().as_deref(), Some("wsl:Ubuntu"));
    }

    #[test]
    fn event_tag_falls_back_when_distro_unknown() {
        let ctx = WslContext {
            distro_name: None,
            in_wsl: true,
        };
        assert_eq!(ctx.event_tag().as_deref(), Some("wsl:unknown"));
    }

    #[test]
    fn event_tag_none_on_bare_linux() {
        let ctx = WslContext {
            distro_name: Some("Ubuntu".into()),
            in_wsl: false,
        };
        assert!(ctx.event_tag().is_none());
    }

    #[test]
    fn parse_text_skips_header_and_marker() {
        let text = "  NAME            STATE           VERSION\n* Ubuntu          Running         2\n  Debian          Stopped         2\n";
        let rows = parse_wsl_list_text(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "Ubuntu");
        assert_eq!(rows[0].state, "Running");
        assert_eq!(rows[0].version, 2);
        assert_eq!(rows[1].name, "Debian");
    }

    #[test]
    fn parse_utf16le_handles_bom_and_real_output_shape() {
        let text = "  NAME    STATE    VERSION\n* Ubuntu  Running  2\n";
        let mut bytes = vec![0xFF, 0xFE]; // BOM
        for c in text.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        let rows = parse_wsl_list_utf16le(&bytes);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "Ubuntu");
    }
}
