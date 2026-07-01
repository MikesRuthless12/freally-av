//! VS-Code-Server / JetBrains-Gateway listener detector
//! (TASK-323, Linux + macOS).
//!
//! The daemon captures `ss -tlnp` (Linux) or
//! `lsof -nP -iTCP -sTCP:LISTEN` (macOS) output. This module
//! parses that capture and flags any listener whose owning
//! process matches a remote-dev binary name AND whose bind
//! address is a non-loopback interface (`0.0.0.0`, `::`, or
//! any concrete public IP).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerRow {
    pub process_name: String,
    pub pid: u32,
    pub bind_address: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteDevListenerFinding {
    pub process_name: String,
    pub pid: u32,
    pub bind_address: String,
    pub port: u16,
}

const REMOTE_DEV_BINARIES: &[&str] = &[
    "code-server",
    "gateway",
    "remote-dev-server.sh",
    "remote-dev-server",
    "rems",
    "vscode-server",
];

pub fn evaluate(listeners: &[ListenerRow]) -> Vec<RemoteDevListenerFinding> {
    let mut out = Vec::new();
    for l in listeners {
        if !is_remote_dev(&l.process_name) {
            continue;
        }
        if is_non_loopback(&l.bind_address) {
            out.push(RemoteDevListenerFinding {
                process_name: l.process_name.clone(),
                pid: l.pid,
                bind_address: l.bind_address.clone(),
                port: l.port,
            });
        }
    }
    out
}

fn is_remote_dev(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    REMOTE_DEV_BINARIES
        .iter()
        .any(|b| lower.contains(&b.to_ascii_lowercase()))
}

fn is_non_loopback(addr: &str) -> bool {
    let a = addr.trim();
    !(a == "127.0.0.1" || a == "::1" || a == "[::1]" || a.starts_with("127."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_code_server_on_wildcard() {
        let rows = vec![ListenerRow {
            process_name: "code-server".to_string(),
            pid: 200,
            bind_address: "0.0.0.0".to_string(),
            port: 8443,
        }];
        let out = evaluate(&rows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].port, 8443);
    }

    #[test]
    fn silent_on_loopback_binding() {
        let rows = vec![ListenerRow {
            process_name: "code-server".to_string(),
            pid: 200,
            bind_address: "127.0.0.1".to_string(),
            port: 8443,
        }];
        assert!(evaluate(&rows).is_empty());
    }

    #[test]
    fn ignores_unrelated_listeners() {
        let rows = vec![ListenerRow {
            process_name: "nginx".to_string(),
            pid: 1,
            bind_address: "0.0.0.0".to_string(),
            port: 80,
        }];
        assert!(evaluate(&rows).is_empty());
    }

    #[test]
    fn flags_jetbrains_gateway() {
        let rows = vec![ListenerRow {
            process_name: "remote-dev-server.sh".to_string(),
            pid: 9,
            bind_address: "10.0.0.5".to_string(),
            port: 5990,
        }];
        let out = evaluate(&rows);
        assert_eq!(out.len(), 1);
    }
}
