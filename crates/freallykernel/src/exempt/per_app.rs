//! Per-app real-time exemption registry (TASK-253, FR-160 cousin).
//!
//! One exemption = `(bundle_id, team_id, optional_path_prefix)`. Bundle
//! ID + Team ID together form the key. Pure path-based exemption is
//! **rejected** at construction — a path-only exemption would let a
//! renamed bundle masquerade as the exempted one.
//!
//! Per `docs/prd.md` § 1.5.4: exemptions just skip the engine call,
//! never relax kernel policy. The macOS daemon stays subscribed to
//! every NOTIFY event; this registry is consulted in user-mode before
//! the IPC frame is sent to the engine.

use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// One exemption record. `bundle_id` is the macOS `CFBundleIdentifier`
/// (`com.example.app`); `team_id` is the 10-character Apple Developer
/// Team ID (`ABCDE12345`). On non-macOS platforms the same shape can
/// be used with platform-equivalent ids (e.g. Windows code-sign subject).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerAppExemption {
    pub bundle_id: String,
    pub team_id: String,
    /// Optional path-prefix scope. When set, the exemption only
    /// matches events whose path starts with this prefix. `None`
    /// means "any path the bundle writes."
    pub path_prefix: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExemptionError {
    #[error("bundle_id required; pure path-based exemption is not allowed (see TASK-253 spec)")]
    MissingBundleId,
    #[error("team_id required; pure path-based exemption is not allowed (see TASK-253 spec)")]
    MissingTeamId,
    #[error(
        "path_prefix must be either omitted or a non-empty string; `Some(\"\")` would match every path"
    )]
    EmptyPathPrefix,
}

impl PerAppExemption {
    /// Validating constructor. Refuses an exemption with empty
    /// bundle_id or team_id — the spec calls those "pure path-based
    /// exemption" and rejects them.
    pub fn new(
        bundle_id: impl Into<String>,
        team_id: impl Into<String>,
        path_prefix: Option<String>,
    ) -> Result<Self, ExemptionError> {
        let bundle_id = bundle_id.into();
        let team_id = team_id.into();
        if bundle_id.is_empty() {
            return Err(ExemptionError::MissingBundleId);
        }
        if team_id.is_empty() {
            return Err(ExemptionError::MissingTeamId);
        }
        // Reject Some("") — would short-circuit matches() to true for
        // every path via `"".starts_with("")` (review CR-3, 2026-05-27).
        // Callers wanting "any path" pass None.
        if matches!(&path_prefix, Some(p) if p.is_empty()) {
            return Err(ExemptionError::EmptyPathPrefix);
        }
        Ok(Self {
            bundle_id,
            team_id,
            path_prefix,
        })
    }

    /// True when this exemption should suppress an event from the
    /// given `(bundle_id, team_id, path)` triple. Both ids must match
    /// exactly; the `path_prefix` (when set) is a substring prefix
    /// check against the canonical path string.
    pub fn matches(&self, bundle_id: &str, team_id: &str, path: &str) -> bool {
        if self.bundle_id != bundle_id || self.team_id != team_id {
            return false;
        }
        if let Some(prefix) = &self.path_prefix {
            path.starts_with(prefix)
        } else {
            true
        }
    }

    /// Stable account key for the platform's secure store. Format:
    /// `<bundle_id>:<team_id>`. Used as the Keychain
    /// `kSecAttrAccount` value on macOS.
    pub fn account_key(&self) -> String {
        format!("{}:{}", self.bundle_id, self.team_id)
    }
}

/// In-memory registry. Backed at startup by a platform-specific
/// loader (Keychain on macOS); mutations re-prompt the user for
/// biometric / system-password unlock at the platform layer, then
/// invalidate this cache so the next event-time check picks up the
/// new list.
#[derive(Debug, Default)]
pub struct ExemptionRegistry {
    inner: RwLock<Vec<PerAppExemption>>,
}

impl ExemptionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn replace(&self, list: Vec<PerAppExemption>) {
        let mut guard = self.inner.write().expect("exemption lock poisoned");
        *guard = list;
    }

    pub fn list(&self) -> Vec<PerAppExemption> {
        self.inner.read().expect("exemption lock poisoned").clone()
    }

    /// True when any exemption matches the event's triple. Designed
    /// for the hot path: a read-lock + linear scan over the small
    /// list. The PRD soft-caps exemption count at 64 per host —
    /// linear scan is fine at that scale.
    pub fn is_exempt(&self, bundle_id: &str, team_id: &str, path: &str) -> bool {
        let guard = self.inner.read().expect("exemption lock poisoned");
        guard.iter().any(|e| e.matches(bundle_id, team_id, path))
    }

    pub fn add(&self, e: PerAppExemption) {
        let mut guard = self.inner.write().expect("exemption lock poisoned");
        // Idempotent: same (bundle, team, path_prefix) triple is a
        // no-op so the UI's add-button doesn't double-write.
        if !guard.iter().any(|x| {
            x.bundle_id == e.bundle_id && x.team_id == e.team_id && x.path_prefix == e.path_prefix
        }) {
            guard.push(e);
        }
    }

    pub fn remove(&self, bundle_id: &str, team_id: &str) -> usize {
        let mut guard = self.inner.write().expect("exemption lock poisoned");
        let before = guard.len();
        guard.retain(|x| !(x.bundle_id == bundle_id && x.team_id == team_id));
        before - guard.len()
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("exemption lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_requires_bundle_id_and_team_id() {
        assert!(matches!(
            PerAppExemption::new("", "ABCDE12345", None),
            Err(ExemptionError::MissingBundleId)
        ));
        assert!(matches!(
            PerAppExemption::new("com.x", "", None),
            Err(ExemptionError::MissingTeamId)
        ));
        assert!(PerAppExemption::new("com.x", "ABCDE12345", None).is_ok());
    }

    #[test]
    fn constructor_rejects_some_empty_path_prefix() {
        // Some("") would match every path via `"".starts_with("")`.
        // Regression for code-review finding CR-3.
        assert!(matches!(
            PerAppExemption::new("com.x", "ABCDE12345", Some(String::new())),
            Err(ExemptionError::EmptyPathPrefix)
        ));
        // None is still accepted as "any path".
        assert!(PerAppExemption::new("com.x", "ABCDE12345", None).is_ok());
        // A non-empty prefix is accepted.
        assert!(PerAppExemption::new("com.x", "ABCDE12345", Some("/Users/me/".into())).is_ok());
    }

    #[test]
    fn matches_requires_both_ids() {
        let e = PerAppExemption::new("com.x", "ABCDE12345", None).unwrap();
        assert!(e.matches("com.x", "ABCDE12345", "/anywhere"));
        assert!(!e.matches("com.y", "ABCDE12345", "/anywhere"));
        assert!(!e.matches("com.x", "FFFFFFFFFF", "/anywhere"));
    }

    #[test]
    fn path_prefix_when_set_is_required() {
        let e = PerAppExemption::new(
            "com.x",
            "ABCDE12345",
            Some("/Users/me/Documents/".to_string()),
        )
        .unwrap();
        assert!(e.matches("com.x", "ABCDE12345", "/Users/me/Documents/x.txt"));
        assert!(!e.matches("com.x", "ABCDE12345", "/Users/me/Other/x.txt"));
    }

    #[test]
    fn account_key_round_trip() {
        let e = PerAppExemption::new("com.x", "ABCDE12345", None).unwrap();
        assert_eq!(e.account_key(), "com.x:ABCDE12345");
    }

    #[test]
    fn registry_add_list_remove() {
        let reg = ExemptionRegistry::new();
        let a = PerAppExemption::new("com.a", "AAAAA00001", None).unwrap();
        let b = PerAppExemption::new("com.b", "BBBBB00002", None).unwrap();
        reg.add(a.clone());
        reg.add(b.clone());
        assert_eq!(reg.len(), 2);
        assert!(reg.is_exempt("com.a", "AAAAA00001", "/x"));
        // Idempotent add — same triple is a no-op.
        reg.add(a.clone());
        assert_eq!(reg.len(), 2);
        let removed = reg.remove("com.a", "AAAAA00001");
        assert_eq!(removed, 1);
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_exempt("com.a", "AAAAA00001", "/x"));
    }

    #[test]
    fn registry_replace_drops_old() {
        let reg = ExemptionRegistry::new();
        reg.add(PerAppExemption::new("com.a", "AAAAA00001", None).unwrap());
        reg.replace(vec![
            PerAppExemption::new("com.b", "BBBBB00002", None).unwrap(),
        ]);
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_exempt("com.a", "AAAAA00001", "/x"));
        assert!(reg.is_exempt("com.b", "BBBBB00002", "/x"));
    }
}
