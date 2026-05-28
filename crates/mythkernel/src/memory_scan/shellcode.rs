//! Shellcode shape detector (TASK-293).
//!
//! Pre-disassembly heuristic looking for the canonical opcode
//! prefixes / patterns used by:
//!
//!   * **GetPC** (`call $+5 ; pop reg`) — `E8 00 00 00 00 58`
//!     and equivalents for ECX/EDX/EBX/EDI/ESI
//!   * **Egg hunter** (`66 81 CA FF 0F`) — SEH egg-hunter
//!     prefix
//!   * **Metasploit reverse_tcp** (`FC E8 82 00 00 00`) — the
//!     stage-0 stub prefix
//!   * **Metasploit reverse_https** (`FC E8 89 00 00 00`) —
//!     also stage-0 stub
//!   * **SC_Loader** (`48 31 C9 48 81 E9`) — common x86-64
//!     shellcode self-decoder prefix
//!
//! Runs only over regions returned by
//! [`super::regions::is_suspicious_region`] — won't sweep
//! every page in process address space.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellcodeShape {
    GetPc,
    EggHunter,
    MetasploitReverseTcp,
    MetasploitReverseHttps,
    Sc64Loader,
    NopSled,
}

impl ShellcodeShape {
    pub fn label(self) -> &'static str {
        match self {
            ShellcodeShape::GetPc => "getpc_stub",
            ShellcodeShape::EggHunter => "egg_hunter",
            ShellcodeShape::MetasploitReverseTcp => "msf_reverse_tcp",
            ShellcodeShape::MetasploitReverseHttps => "msf_reverse_https",
            ShellcodeShape::Sc64Loader => "sc64_loader",
            ShellcodeShape::NopSled => "long_nop_sled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellcodeShapeFinding {
    pub shape: ShellcodeShape,
    pub offset: usize,
}

const SIGS: &[(ShellcodeShape, &[u8])] = &[
    // GetPC: `call $+5 ; pop eax` (variants for other regs all
    // share the `E8 00 00 00 00` prefix).
    (ShellcodeShape::GetPc, &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58]),
    (ShellcodeShape::GetPc, &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x59]), // pop ecx
    (ShellcodeShape::GetPc, &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A]), // pop edx
    (ShellcodeShape::GetPc, &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B]), // pop ebx
    (ShellcodeShape::GetPc, &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E]), // pop esi
    (ShellcodeShape::GetPc, &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5F]), // pop edi
    (ShellcodeShape::EggHunter, &[0x66, 0x81, 0xCA, 0xFF, 0x0F]),
    (
        ShellcodeShape::MetasploitReverseTcp,
        &[0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00],
    ),
    (
        ShellcodeShape::MetasploitReverseHttps,
        &[0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00],
    ),
    (
        ShellcodeShape::Sc64Loader,
        &[0x48, 0x31, 0xC9, 0x48, 0x81, 0xE9],
    ),
];

const NOP_SLED_THRESHOLD: usize = 32;

pub fn scan_shellcode_shapes(bytes: &[u8]) -> Vec<ShellcodeShapeFinding> {
    let mut out = Vec::new();
    let mut seen: Vec<ShellcodeShape> = Vec::new();
    for (shape, needle) in SIGS {
        if seen.contains(shape) {
            continue;
        }
        if let Some(off) = find_subslice(bytes, needle) {
            out.push(ShellcodeShapeFinding {
                shape: *shape,
                offset: off,
            });
            seen.push(*shape);
        }
    }
    if let Some(off) = find_nop_sled(bytes) {
        if !seen.contains(&ShellcodeShape::NopSled) {
            out.push(ShellcodeShapeFinding {
                shape: ShellcodeShape::NopSled,
                offset: off,
            });
        }
    }
    out
}

fn find_nop_sled(bytes: &[u8]) -> Option<usize> {
    let mut start: Option<usize> = None;
    let mut run = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0x90 {
            if start.is_none() {
                start = Some(i);
            }
            run += 1;
            if run >= NOP_SLED_THRESHOLD {
                return start;
            }
        } else {
            start = None;
            run = 0;
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_getpc_stub() {
        let bytes = [0x00u8, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x90, 0x90];
        let findings = scan_shellcode_shapes(&bytes);
        assert!(findings.iter().any(|f| f.shape == ShellcodeShape::GetPc));
    }

    #[test]
    fn detects_metasploit_reverse_tcp_prefix() {
        let bytes = [0xFCu8, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5];
        let findings = scan_shellcode_shapes(&bytes);
        assert!(
            findings
                .iter()
                .any(|f| f.shape == ShellcodeShape::MetasploitReverseTcp)
        );
    }

    #[test]
    fn detects_long_nop_sled() {
        let bytes = vec![0x90u8; 64];
        let findings = scan_shellcode_shapes(&bytes);
        assert!(findings.iter().any(|f| f.shape == ShellcodeShape::NopSled));
    }

    #[test]
    fn ignores_short_nop_run() {
        let mut bytes = vec![0u8; 10];
        bytes.extend(std::iter::repeat(0x90u8).take(8));
        bytes.extend(std::iter::repeat(0u8).take(10));
        let findings = scan_shellcode_shapes(&bytes);
        assert!(findings.iter().all(|f| f.shape != ShellcodeShape::NopSled));
    }

    #[test]
    fn detects_egg_hunter_prefix() {
        let mut bytes = vec![0u8; 8];
        bytes.extend_from_slice(&[0x66, 0x81, 0xCA, 0xFF, 0x0F]);
        let findings = scan_shellcode_shapes(&bytes);
        assert!(
            findings
                .iter()
                .any(|f| f.shape == ShellcodeShape::EggHunter)
        );
    }

    #[test]
    fn random_bytes_yield_no_findings() {
        let bytes: Vec<u8> = (0..256).map(|i| (i & 0xFF) as u8).collect();
        let findings = scan_shellcode_shapes(&bytes);
        assert!(findings.is_empty());
    }

    #[test]
    fn duplicate_shape_only_once() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58]);
        bytes.extend(std::iter::repeat(0u8).take(16));
        bytes.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x59]);
        let findings = scan_shellcode_shapes(&bytes);
        let getpc_count = findings
            .iter()
            .filter(|f| f.shape == ShellcodeShape::GetPc)
            .count();
        assert_eq!(getpc_count, 1);
    }
}
