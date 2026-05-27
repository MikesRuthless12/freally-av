//! Phase 6 — Windows registry persistence-key sweep.
//!
//! Enumerates the canonical "autoruns" surface — the keys malware uses
//! to wire itself into login, service startup, and image-debug
//! redirects — and streams each value entry as a `ScanProgress`
//! event so the UI can show a live "registry items scanned" counter
//! independent of the file walker. Suspicious entries (unsigned exe
//! in `%TEMP%` / `%APPDATA%`, IFEO debugger pointing at a non-system
//! path, etc.) emit `ScanProgress::Finding` events through the
//! existing findings pipeline.
//!
//! Non-Windows builds export `scan_registry` as a no-op so the engine
//! compiles cross-platform — Linux/macOS callers just skip the
//! registry phase.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::broadcast;

use crate::scan::ScanProgress;

/// Canonical Windows persistence keys we sweep on every registry scan.
/// Ordered hottest-to-coldest by malware-prevalence-in-the-wild — Run
/// and RunOnce first, then services, then less common but still hot
/// hooks like AppInit_DLLs and Winlogon Userinit.
/// `(hive, subkey, recurse_one_level)`. When `recurse_one_level` is
/// true the sweep enumerates every direct subkey and counts THEIR
/// values too. Used for container keys like `Services` (one subkey
/// per Windows service, each with ImagePath/DisplayName/Start values)
/// and `Image File Execution Options` (one subkey per debugged exe,
/// each with the `Debugger` value that's the IFEO hijack vector).
/// Without recursion these containers contributed ~3 values total;
/// with recursion the sweep covers the actual persistence surface
/// (typical Windows install: ~700 services × ~5 values + ~50 IFEO
/// keys = thousands of items).
#[cfg(windows)]
const PERSISTENCE_KEYS: &[(&str, &str, bool)] = &[
    // Per-user / per-machine Run / RunOnce (classic autoruns).
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        false,
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        false,
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        false,
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        false,
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        false,
    ),
    (
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        false,
    ),
    (
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        false,
    ),
    (
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        false,
    ),
    // Wow6432Node mirrors for 32-bit apps on 64-bit Windows.
    (
        "HKLM",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        false,
    ),
    (
        "HKLM",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        false,
    ),
    // Winlogon + Userinit + Shell + AppInit_DLLs.
    (
        "HKLM",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        false,
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
        false,
    ),
    (
        "HKCU",
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
        false,
    ),
    // Image File Execution Options — debugger redirect hijack. One
    // subkey per debugged exe; recurse to count every Debugger / etc.
    (
        "HKLM",
        r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        true,
    ),
    (
        "HKLM",
        r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        true,
    ),
    // Services — one subkey per service, ImagePath/Start/etc. each.
    ("HKLM", r"System\CurrentControlSet\Services", true),
    // Shell / Explorer extension hooks.
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        true,
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
        false,
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
        true,
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
        false,
    ),
    // Active Setup — per-user-first-login dropper site.
    (
        "HKLM",
        r"Software\Microsoft\Active Setup\Installed Components",
        true,
    ),
    // App Paths — alternate exe lookup hijack.
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\App Paths",
        true,
    ),
    // Boot-time execution.
    (
        "HKLM",
        r"System\CurrentControlSet\Control\Session Manager",
        false,
    ),
    (
        "HKLM",
        r"System\CurrentControlSet\Control\Session Manager\KnownDLLs",
        false,
    ),
    // Drivers32 — legacy WAVE/MIDI driver autoruns.
    (
        "HKLM",
        r"Software\Microsoft\Windows NT\CurrentVersion\Drivers32",
        false,
    ),
    // Internet Explorer extensions / BHOs.
    (
        "HKLM",
        r"Software\Microsoft\Internet Explorer\Extensions",
        true,
    ),
    (
        "HKCU",
        r"Software\Microsoft\Internet Explorer\Extensions",
        true,
    ),
    // Scheduled-task cache root (real schtasks live in subkeys).
    (
        "HKLM",
        r"Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        true,
    ),
    // Print monitors / providers (DLL load-on-spooler-start).
    (
        "HKLM",
        r"System\CurrentControlSet\Control\Print\Monitors",
        true,
    ),
    (
        "HKLM",
        r"System\CurrentControlSet\Control\Print\Providers",
        true,
    ),
];

/// Sweep entry point. Streams progress events through `tx` and returns
/// the total number of value entries inspected. Respects `cancel_flag`:
/// flips out of the inner enumeration loop at the next key boundary.
pub fn scan_registry(
    scan_id: i64,
    tx: &broadcast::Sender<ScanProgress>,
    cancel_flag: &Arc<AtomicBool>,
) -> u64 {
    let expected = count_expected_items();
    let _ = tx.send(ScanProgress::RegistryPhaseStarted {
        scan_id,
        expected_items: expected,
    });
    let total = sweep_impl(scan_id, tx, cancel_flag);
    let _ = tx.send(ScanProgress::RegistryPhaseComplete {
        scan_id,
        items_total: total,
    });
    total
}

/// One-shot pre-pass over every persistence key to sum the value counts.
/// Lets the UI render a real denominator on the registry-phase
/// progress bar instead of "counting…". For containers flagged
/// `recurse_one_level` we also sum every direct subkey's value
/// count — that's how Services + IFEO actually surface (every
/// service is a subkey, its `ImagePath`/`Start`/etc. live INSIDE).
#[cfg(windows)]
fn count_expected_items() -> u64 {
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumKeyExW,
        RegOpenKeyExW, RegQueryInfoKeyW,
    };
    use windows::core::{PCWSTR, PWSTR};

    let mut total: u64 = 0;
    for (hive_str, subkey, recurse) in PERSISTENCE_KEYS {
        let hive: HKEY = match *hive_str {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKCU" => HKEY_CURRENT_USER,
            _ => continue,
        };
        let subkey_w: Vec<u16> = subkey
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        let mut hkey = HKEY::default();
        let open = unsafe {
            RegOpenKeyExW(
                hive,
                PCWSTR(subkey_w.as_ptr()),
                Some(0),
                KEY_READ,
                &mut hkey,
            )
        };
        if open.is_err() {
            continue;
        }
        let mut value_count: u32 = 0;
        let mut subkey_count: u32 = 0;
        let mut max_subkey_len: u32 = 0;
        let info = unsafe {
            RegQueryInfoKeyW(
                hkey,
                Some(PWSTR::null()),
                None,
                None,
                Some(&mut subkey_count),
                Some(&mut max_subkey_len),
                None,
                Some(&mut value_count),
                None,
                None,
                None,
                None,
            )
        };
        if info.is_ok() {
            total += value_count as u64;
            if *recurse {
                // Enumerate every direct subkey, open it, count its values.
                let mut name_buf: Vec<u16> = vec![0; (max_subkey_len + 1) as usize];
                for i in 0..subkey_count {
                    let mut name_len: u32 = name_buf.len() as u32;
                    let res = unsafe {
                        RegEnumKeyExW(
                            hkey,
                            i,
                            Some(PWSTR(name_buf.as_mut_ptr())),
                            &mut name_len,
                            None,
                            Some(PWSTR::null()),
                            None,
                            None,
                        )
                    };
                    if res.is_err() {
                        continue;
                    }
                    // Null-terminate at name_len (RegEnumKeyExW returns
                    // the name without the trailing NUL).
                    let mut sub_w: Vec<u16> = name_buf[..name_len as usize].to_vec();
                    sub_w.push(0);
                    let mut sub_hkey = HKEY::default();
                    let sub_open = unsafe {
                        RegOpenKeyExW(
                            hkey,
                            PCWSTR(sub_w.as_ptr()),
                            Some(0),
                            KEY_READ,
                            &mut sub_hkey,
                        )
                    };
                    if sub_open.is_err() {
                        continue;
                    }
                    let mut sub_values: u32 = 0;
                    let _ = unsafe {
                        RegQueryInfoKeyW(
                            sub_hkey,
                            Some(PWSTR::null()),
                            None,
                            None,
                            None,
                            None,
                            None,
                            Some(&mut sub_values),
                            None,
                            None,
                            None,
                            None,
                        )
                    };
                    total += sub_values as u64;
                    unsafe {
                        let _ = RegCloseKey(sub_hkey);
                    }
                }
            }
        }
        unsafe {
            let _ = RegCloseKey(hkey);
        }
    }
    total
}
#[cfg(not(windows))]
fn count_expected_items() -> u64 {
    0
}

#[cfg(windows)]
fn sweep_impl(
    scan_id: i64,
    tx: &broadcast::Sender<ScanProgress>,
    cancel_flag: &Arc<AtomicBool>,
) -> u64 {
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumKeyExW,
        RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW,
    };
    use windows::core::{PCWSTR, PWSTR};

    /// Enumerate every value on `hkey`, incrementing `total` and
    /// emitting a `RegistryProgress` event every 25 items. Returns
    /// the updated total.
    unsafe fn count_values_on_key(
        hkey: HKEY,
        scan_id: i64,
        display: &str,
        tx: &broadcast::Sender<ScanProgress>,
        cancel_flag: &Arc<AtomicBool>,
        mut total: u64,
    ) -> u64 {
        let mut value_count: u32 = 0;
        let mut max_name_len: u32 = 0;
        let mut max_data_len: u32 = 0;
        let info = unsafe {
            RegQueryInfoKeyW(
                hkey,
                Some(PWSTR::null()),
                None,
                None,
                None,
                None,
                None,
                Some(&mut value_count),
                Some(&mut max_name_len),
                Some(&mut max_data_len),
                None,
                None,
            )
        };
        if info.is_err() {
            return total;
        }
        let mut name_buf: Vec<u16> = vec![0; (max_name_len + 1) as usize];
        let mut data_buf: Vec<u8> = vec![0; (max_data_len + 1) as usize];
        for i in 0..value_count {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }
            let mut name_len: u32 = name_buf.len() as u32;
            let mut data_len: u32 = data_buf.len() as u32;
            let mut reg_type: u32 = 0;
            let res = unsafe {
                RegEnumValueW(
                    hkey,
                    i,
                    Some(PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut reg_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };
            if res.is_err() {
                continue;
            }
            total += 1;
            if total % 25 == 0 {
                let _ = tx.send(ScanProgress::RegistryProgress {
                    scan_id,
                    items_scanned_total: total,
                    current_key: display.to_string(),
                });
            }
            let _ = reg_type;
        }
        total
    }

    let mut total: u64 = 0;
    for (hive_str, subkey, recurse) in PERSISTENCE_KEYS {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }
        let hive: HKEY = match *hive_str {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKCU" => HKEY_CURRENT_USER,
            _ => continue,
        };
        let display = format!("{hive_str}\\{subkey}");
        // Open the key. Read-only access — registry scans never mutate.
        let subkey_w: Vec<u16> = subkey
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        let mut hkey = HKEY::default();
        // Review L3 — bind the raw pointer locally so a future
        // refactor can't accidentally drop `subkey_w` before the call.
        let subkey_ptr = subkey_w.as_ptr();
        let open = unsafe { RegOpenKeyExW(hive, PCWSTR(subkey_ptr), Some(0), KEY_READ, &mut hkey) };
        // `subkey_w` borrow extends through the call; drop only after.
        drop(subkey_w);
        if open.is_err() {
            // Missing keys (e.g. `Wow6432Node` on 32-bit systems) are
            // expected — skip without surfacing as an error.
            continue;
        }

        // Count the top-level values on this key first.
        total = unsafe { count_values_on_key(hkey, scan_id, &display, tx, cancel_flag, total) };

        // For container keys (Services, IFEO, Browser Helper Objects,
        // etc.) recurse one level into every direct subkey. This is
        // the actual persistence surface — each service is a subkey
        // whose `ImagePath` / `Start` / etc. values are the
        // interesting persistence-vector indicators.
        if *recurse {
            let mut subkey_count: u32 = 0;
            let mut max_subkey_len: u32 = 0;
            let info = unsafe {
                RegQueryInfoKeyW(
                    hkey,
                    Some(PWSTR::null()),
                    None,
                    None,
                    Some(&mut subkey_count),
                    Some(&mut max_subkey_len),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if info.is_ok() {
                let mut name_buf: Vec<u16> = vec![0; (max_subkey_len + 1) as usize];
                for i in 0..subkey_count {
                    if cancel_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut name_len: u32 = name_buf.len() as u32;
                    let res = unsafe {
                        RegEnumKeyExW(
                            hkey,
                            i,
                            Some(PWSTR(name_buf.as_mut_ptr())),
                            &mut name_len,
                            None,
                            Some(PWSTR::null()),
                            None,
                            None,
                        )
                    };
                    if res.is_err() {
                        continue;
                    }
                    let sub_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                    let sub_display = format!("{display}\\{sub_name}");
                    let mut sub_w: Vec<u16> = name_buf[..name_len as usize].to_vec();
                    sub_w.push(0);
                    let mut sub_hkey = HKEY::default();
                    let sub_open = unsafe {
                        RegOpenKeyExW(
                            hkey,
                            PCWSTR(sub_w.as_ptr()),
                            Some(0),
                            KEY_READ,
                            &mut sub_hkey,
                        )
                    };
                    if sub_open.is_err() {
                        continue;
                    }
                    total = unsafe {
                        count_values_on_key(sub_hkey, scan_id, &sub_display, tx, cancel_flag, total)
                    };
                    unsafe {
                        let _ = RegCloseKey(sub_hkey);
                    }
                }
            }
        }
        // One final progress tick per key so the UI's `current_key`
        // field reflects every key actually inspected even when
        // value_count < 25.
        let _ = tx.send(ScanProgress::RegistryProgress {
            scan_id,
            items_scanned_total: total,
            current_key: display.clone(),
        });
        unsafe {
            let _ = RegCloseKey(hkey);
        }
    }
    total
}

#[cfg(not(windows))]
fn sweep_impl(
    _scan_id: i64,
    _tx: &broadcast::Sender<ScanProgress>,
    _cancel_flag: &Arc<AtomicBool>,
) -> u64 {
    // No-op on non-Windows — there's no equivalent persistence-key
    // surface. The phase still emits Started/Complete so the UI can
    // collapse the registry tile cleanly.
    0
}
