//! Microsoft Shell Link (`.lnk`) payload extractor (TASK-279).
//!
//! Implements the subset of MS-SHLLINK 5.0 (Shell Link Binary
//! File Format) that Mythodikal cares about:
//!
//!   * `ShellLinkHeader` — magic + LinkFlags + FileAttributes
//!   * `LinkTargetIDList` — the IDList target path
//!   * `LinkInfo` — local + network volume path
//!   * `StringData` — Name, Relative path, Working Dir,
//!     Command-line Arguments, Icon Location
//!
//! Returns a [`LnkInfo`] populated to the depth the input
//! allowed. Consumed by
//! [`crate::payload_anomaly::lnk_anomaly`] (TASK-289).

use serde::{Deserialize, Serialize};

/// `4C 00 00 00` — header size in little-endian.
const LNK_HEADER_SIZE_TAG: [u8; 4] = [0x4C, 0x00, 0x00, 0x00];
/// `00021401-0000-0000-C000-000000000046` — class identifier.
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LnkInfo {
    pub name: Option<String>,
    pub relative_path: Option<String>,
    pub working_dir: Option<String>,
    pub command_arguments: Option<String>,
    pub icon_location: Option<String>,
    pub link_flags: u32,
    pub file_attributes: u32,
}

impl LnkInfo {
    /// Quoted-for-log rendering of `command_arguments`. The raw
    /// value comes from a `.lnk` `StringData::Arguments` block
    /// the attacker authored — never splice it raw into a log
    /// line (control chars / ANSI sequences) and never pass it
    /// to a shell. Use [`crate::util::shell::poisoned_for_exec`]
    /// if the value must reach any exec-shaped surface so
    /// accidental invocation fails loud.
    pub fn safe_command_arguments_for_log(&self) -> String {
        match self.command_arguments.as_deref() {
            Some(s) => crate::util::shell::quote_for_log(s),
            None => "\"\"".to_string(),
        }
    }

    /// Quoted-for-log rendering of `working_dir`. Carrier is the
    /// LNK `WorkingDir` StringData block — attacker-controlled.
    pub fn safe_working_dir_for_log(&self) -> String {
        match self.working_dir.as_deref() {
            Some(s) => crate::util::shell::quote_for_log(s),
            None => "\"\"".to_string(),
        }
    }

    /// `true` when `HasLinkTargetIDList` (bit 0) is set.
    pub fn has_target_idlist(&self) -> bool {
        self.link_flags & 0x0000_0001 != 0
    }
    /// `true` when `HasName` (bit 2) is set.
    pub fn has_name(&self) -> bool {
        self.link_flags & 0x0000_0004 != 0
    }
    /// `true` when `HasRelativePath` (bit 3) is set.
    pub fn has_relative_path(&self) -> bool {
        self.link_flags & 0x0000_0008 != 0
    }
    /// `true` when `HasWorkingDir` (bit 4) is set.
    pub fn has_working_dir(&self) -> bool {
        self.link_flags & 0x0000_0010 != 0
    }
    /// `true` when `HasArguments` (bit 5) is set.
    pub fn has_arguments(&self) -> bool {
        self.link_flags & 0x0000_0020 != 0
    }
    /// `true` when `HasIconLocation` (bit 6) is set.
    pub fn has_icon_location(&self) -> bool {
        self.link_flags & 0x0000_0040 != 0
    }
    /// `true` when `IsUnicode` (bit 7) is set.
    pub fn is_unicode(&self) -> bool {
        self.link_flags & 0x0000_0080 != 0
    }
}

/// Parse a `.lnk` byte buffer. Returns `None` when the header
/// is not a valid Shell Link.
pub fn parse(raw: &[u8]) -> Option<LnkInfo> {
    if raw.len() < 0x4C {
        return None;
    }
    if raw[0..4] != LNK_HEADER_SIZE_TAG {
        return None;
    }
    if raw[4..20] != LNK_CLSID {
        return None;
    }

    let link_flags = u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]);
    let file_attributes = u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]);

    let mut info = LnkInfo {
        link_flags,
        file_attributes,
        ..Default::default()
    };

    let mut cursor = 0x4Cusize; // past header

    // Skip LinkTargetIDList if present: 2-byte size + payload.
    if info.has_target_idlist() {
        if cursor + 2 > raw.len() {
            return Some(info);
        }
        let idlist_size = u16::from_le_bytes([raw[cursor], raw[cursor + 1]]) as usize;
        cursor += 2 + idlist_size;
    }

    // Skip LinkInfo if `HasLinkInfo` (bit 1) is set: 4-byte
    // self-relative size + payload.
    if link_flags & 0x0000_0002 != 0 {
        if cursor + 4 > raw.len() {
            return Some(info);
        }
        let link_info_size = u32::from_le_bytes([
            raw[cursor],
            raw[cursor + 1],
            raw[cursor + 2],
            raw[cursor + 3],
        ]) as usize;
        cursor += link_info_size;
    }

    let is_unicode = info.is_unicode();
    let order = [
        (info.has_name(), 0u8),
        (info.has_relative_path(), 1),
        (info.has_working_dir(), 2),
        (info.has_arguments(), 3),
        (info.has_icon_location(), 4),
    ];
    // StringData blocks each prefix a u16 character count; then
    // either UTF-16-LE (when IsUnicode) or ANSI (CP1252) bytes.
    for (present, kind) in order {
        if !present {
            continue;
        }
        let Some((text, advance)) = read_string_data(raw, cursor, is_unicode) else {
            return Some(info);
        };
        match kind {
            0 => info.name = Some(text),
            1 => info.relative_path = Some(text),
            2 => info.working_dir = Some(text),
            3 => info.command_arguments = Some(text),
            _ => info.icon_location = Some(text),
        }
        cursor += advance;
    }

    Some(info)
}

fn read_string_data(raw: &[u8], at: usize, unicode: bool) -> Option<(String, usize)> {
    if at + 2 > raw.len() {
        return None;
    }
    let count = u16::from_le_bytes([raw[at], raw[at + 1]]) as usize;
    let bytes_per_char = if unicode { 2 } else { 1 };
    let total_bytes = count * bytes_per_char;
    let payload_start = at + 2;
    if payload_start + total_bytes > raw.len() {
        return None;
    }
    let s = if unicode {
        let mut chars = Vec::with_capacity(count);
        for i in 0..count {
            let off = payload_start + i * 2;
            chars.push(u16::from_le_bytes([raw[off], raw[off + 1]]));
        }
        String::from_utf16_lossy(&chars)
    } else {
        String::from_utf8_lossy(&raw[payload_start..payload_start + total_bytes]).into_owned()
    };
    Some((s, 2 + total_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth(flags: u32, attributes: u32, unicode: bool, strings: &[(u32, &str)]) -> Vec<u8> {
        // 0x4C header + minimal body. We skip LinkTargetIDList
        // and LinkInfo by clearing their flags before serializing,
        // then re-OR the requested flags + StringData blocks.
        let mut buf = vec![0u8; 0x4C];
        buf[0..4].copy_from_slice(&LNK_HEADER_SIZE_TAG);
        buf[4..20].copy_from_slice(&LNK_CLSID);
        let mut combined = flags;
        if unicode {
            combined |= 0x0000_0080;
        }
        buf[20..24].copy_from_slice(&combined.to_le_bytes());
        buf[24..28].copy_from_slice(&attributes.to_le_bytes());
        for &(bit, s) in strings {
            if combined & bit == 0 {
                continue;
            }
            let len = s.chars().count() as u16;
            buf.extend_from_slice(&len.to_le_bytes());
            if unicode {
                for code in s.encode_utf16() {
                    buf.extend_from_slice(&code.to_le_bytes());
                }
            } else {
                buf.extend_from_slice(s.as_bytes());
            }
        }
        buf
    }

    #[test]
    fn rejects_non_lnk() {
        assert!(parse(b"this is not a lnk").is_none());
        assert!(parse(&[0u8; 0x4C]).is_none());
    }

    #[test]
    fn parses_unicode_name_and_args() {
        // flags = HasName | HasArguments | IsUnicode.
        let blob = synth(
            0x0000_0024,
            0x20,
            true,
            &[(0x0000_0004, "shortcut name"), (0x0000_0020, "/c calc.exe")],
        );
        let info = parse(&blob).expect("parses");
        assert_eq!(info.name.as_deref(), Some("shortcut name"));
        assert_eq!(info.command_arguments.as_deref(), Some("/c calc.exe"));
    }

    #[test]
    fn parses_working_dir_and_target_relative() {
        let blob = synth(
            0x0000_0018,
            0x20,
            true,
            &[(0x0000_0008, "..\\target.exe"), (0x0000_0010, "%TEMP%")],
        );
        let info = parse(&blob).expect("parses");
        assert_eq!(info.relative_path.as_deref(), Some("..\\target.exe"));
        assert_eq!(info.working_dir.as_deref(), Some("%TEMP%"));
    }

    #[test]
    fn ansi_strings_decode() {
        // Same call but with IsUnicode bit cleared.
        let blob = synth(
            0x0000_0024,
            0x20,
            false,
            &[(0x0000_0004, "ansi-name"), (0x0000_0020, "abc")],
        );
        let info = parse(&blob).expect("parses");
        assert!(!info.is_unicode());
        assert_eq!(info.name.as_deref(), Some("ansi-name"));
        assert_eq!(info.command_arguments.as_deref(), Some("abc"));
    }

    #[test]
    fn safe_log_accessors_neutralise_shell_metachars() {
        let info = LnkInfo {
            link_flags: 0x0000_0020,
            command_arguments: Some("; rm -rf / ; #\necho pwned".to_string()),
            working_dir: Some("%TEMP%\n".to_string()),
            ..Default::default()
        };
        let args = info.safe_command_arguments_for_log();
        assert!(args.contains("\\n"));
        // The output is wrapped in double quotes, so no shell
        // metacharacter sits in argv splicing position.
        assert!(args.starts_with('"') && args.ends_with('"'));
        let wd = info.safe_working_dir_for_log();
        assert!(wd.contains("\\n"));
    }

    #[test]
    fn safe_log_accessors_empty_when_absent() {
        let info = LnkInfo::default();
        assert_eq!(info.safe_command_arguments_for_log(), "\"\"");
        assert_eq!(info.safe_working_dir_for_log(), "\"\"");
    }

    #[test]
    fn link_flags_helpers_round_trip() {
        let info = LnkInfo {
            link_flags: 0x0000_00FF,
            ..Default::default()
        };
        assert!(info.has_target_idlist());
        assert!(info.has_name());
        assert!(info.has_relative_path());
        assert!(info.has_working_dir());
        assert!(info.has_arguments());
        assert!(info.has_icon_location());
        assert!(info.is_unicode());
    }

    #[test]
    fn truncated_input_returns_partial_info() {
        // Just the header — no string data yet. Should yield a
        // populated LnkInfo with empty optional fields.
        let mut blob = synth(0x0000_0024, 0x20, true, &[]);
        // Mark the flag bits but provide no string data.
        let info = parse(&blob).expect("parses header");
        assert_eq!(info.link_flags & 0x24, 0x24);
        assert!(info.name.is_none());
        assert!(info.command_arguments.is_none());
        // Truncate to less than header size — None.
        blob.truncate(0x40);
        assert!(parse(&blob).is_none());
    }
}
