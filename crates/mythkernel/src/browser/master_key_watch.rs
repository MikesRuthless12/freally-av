//! Browser master-key file watchdog (TASK-262, FEAT-207, Phase 10 Wave 2).
//!
//! Extends the existing sensitive-file watch (TASK-141) to every
//! browser's password/cookie/master-key file. The catalogue here
//! identifies the per-browser sensitive-file set; the daemon side
//! subscribes to FS open / read events and consults
//! [`is_sensitive_file`] to decide whether to surface a finding when
//! a non-browser process opens the path. NOTIFY-only.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveFileKind {
    /// Chromium `Local State` — holds the per-install master key
    /// (DPAPI-encrypted on Windows, Keychain-bound on macOS).
    LocalState,
    /// Chromium `Login Data` SQLite — saved-password rows.
    LoginData,
    /// Chromium `Cookies` SQLite.
    Cookies,
    /// Chromium `Web Data` SQLite — autofill, payment methods, …
    WebData,
    /// Firefox `key4.db` — encrypted master-key store.
    FirefoxKey4,
    /// Firefox `logins.json` — saved-password ciphertext.
    FirefoxLogins,
    /// Firefox `cookies.sqlite`.
    FirefoxCookies,
}

impl SensitiveFileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SensitiveFileKind::LocalState => "local_state",
            SensitiveFileKind::LoginData => "login_data",
            SensitiveFileKind::Cookies => "cookies",
            SensitiveFileKind::WebData => "web_data",
            SensitiveFileKind::FirefoxKey4 => "firefox_key4",
            SensitiveFileKind::FirefoxLogins => "firefox_logins",
            SensitiveFileKind::FirefoxCookies => "firefox_cookies",
        }
    }
}

/// One sensitive file the daemon should subscribe to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveFile {
    pub family: super::BrowserFamily,
    pub kind: SensitiveFileKind,
    pub path: PathBuf,
}

/// Canonical Chromium sensitive-file basenames present in every
/// profile directory.
const CHROMIUM_PROFILE_FILES: &[(SensitiveFileKind, &str)] = &[
    (SensitiveFileKind::LoginData, "Login Data"),
    (SensitiveFileKind::Cookies, "Network/Cookies"),
    (SensitiveFileKind::WebData, "Web Data"),
];

/// Canonical Firefox sensitive-file basenames.
const FIREFOX_PROFILE_FILES: &[(SensitiveFileKind, &str)] = &[
    (SensitiveFileKind::FirefoxKey4, "key4.db"),
    (SensitiveFileKind::FirefoxLogins, "logins.json"),
    (SensitiveFileKind::FirefoxCookies, "cookies.sqlite"),
];

/// Walk every supplied root and emit one [`SensitiveFile`] per
/// existing sensitive file. Files that do not exist are silently
/// dropped — the watch list adjusts as profiles come and go.
pub fn enumerate(roots: &super::BrowserRoots) -> Vec<SensitiveFile> {
    let mut out = Vec::new();
    for (family, root) in roots.iter() {
        if family.is_chromium() {
            // Chromium `Local State` lives at the user-data-root,
            // not under each profile.
            let local_state = root.join("Local State");
            if local_state.is_file() {
                out.push(SensitiveFile {
                    family,
                    kind: SensitiveFileKind::LocalState,
                    path: local_state,
                });
            }
            for profile in super::chromium_profile_dirs(root) {
                for (kind, sub) in CHROMIUM_PROFILE_FILES {
                    let path = profile.join(sub);
                    if path.is_file() {
                        out.push(SensitiveFile {
                            family,
                            kind: *kind,
                            path,
                        });
                    } else {
                        // Pre-Network-Service Chromium kept `Cookies`
                        // at the profile root.
                        if *kind == SensitiveFileKind::Cookies {
                            let legacy = profile.join("Cookies");
                            if legacy.is_file() {
                                out.push(SensitiveFile {
                                    family,
                                    kind: *kind,
                                    path: legacy,
                                });
                            }
                        }
                    }
                }
            }
        } else if family == super::BrowserFamily::Firefox {
            for profile in super::firefox_profile_dirs(root) {
                for (kind, sub) in FIREFOX_PROFILE_FILES {
                    let path = profile.join(sub);
                    if path.is_file() {
                        out.push(SensitiveFile {
                            family,
                            kind: *kind,
                            path,
                        });
                    }
                }
            }
        }
    }
    out
}

/// Reverse lookup: does `path` exactly equal a path emitted by
/// [`enumerate`]? Daemon side calls this when an FS open event
/// arrives.
pub fn is_sensitive_file(path: &Path, list: &[SensitiveFile]) -> Option<SensitiveFileKind> {
    list.iter().find(|sf| sf.path == path).map(|sf| sf.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, b"").unwrap();
    }

    #[test]
    fn chromium_enumeration_finds_per_profile_sensitive_files() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        touch(&user_data.join("Local State"));
        let profile = user_data.join("Default");
        touch(&profile.join("Login Data"));
        touch(&profile.join("Network/Cookies"));
        touch(&profile.join("Web Data"));
        let roots = super::super::BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        let list = enumerate(&roots);
        let kinds: Vec<SensitiveFileKind> = list.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SensitiveFileKind::LocalState));
        assert!(kinds.contains(&SensitiveFileKind::LoginData));
        assert!(kinds.contains(&SensitiveFileKind::Cookies));
        assert!(kinds.contains(&SensitiveFileKind::WebData));
    }

    #[test]
    fn cookies_fallback_to_legacy_path_when_network_missing() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        let profile = user_data.join("Default");
        touch(&profile.join("Cookies"));
        let roots = super::super::BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        let list = enumerate(&roots);
        assert!(list.iter().any(|s| s.kind == SensitiveFileKind::Cookies));
    }

    #[test]
    fn firefox_enumeration_picks_up_master_key_logins_and_cookies() {
        let dir = tempdir().unwrap();
        let profiles_root = dir.path();
        let profile = profiles_root.join("abc.default-release");
        std::fs::create_dir_all(&profile).unwrap();
        touch(&profile.join("prefs.js"));
        touch(&profile.join("key4.db"));
        touch(&profile.join("logins.json"));
        touch(&profile.join("cookies.sqlite"));
        let roots = super::super::BrowserRoots {
            firefox: vec![profiles_root.to_path_buf()],
            ..Default::default()
        };
        let list = enumerate(&roots);
        assert_eq!(list.len(), 3);
        assert!(
            list.iter()
                .all(|s| s.family == super::super::BrowserFamily::Firefox)
        );
    }

    #[test]
    fn missing_files_are_silently_skipped() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Default")).unwrap();
        let roots = super::super::BrowserRoots {
            chrome: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        assert!(enumerate(&roots).is_empty());
    }

    #[test]
    fn is_sensitive_file_reverse_lookup() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        let profile = user_data.join("Default");
        let login = profile.join("Login Data");
        touch(&login);
        let roots = super::super::BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        let list = enumerate(&roots);
        assert_eq!(
            is_sensitive_file(&login, &list),
            Some(SensitiveFileKind::LoginData)
        );
        assert_eq!(is_sensitive_file(&PathBuf::from("/elsewhere"), &list), None);
    }
}
