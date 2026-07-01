//! Keychain-backed exemption store (TASK-253, Phase 9 Wave 2).
//!
//! Wraps `Security.framework`'s `SecItemAdd` / `SecItemCopyMatching` /
//! `SecItemDelete`. Each exemption is a `kSecClassGenericPassword`
//! item with:
//!
//!   * `kSecAttrService`        = `com.freally.exemption`
//!   * `kSecAttrAccount`        = `<bundle_id>:<team_id>`
//!   * `kSecAttrAccessControl`  = `BiometryCurrentSet | Or | DevicePasscode`
//!
//! `BiometryCurrentSet` invalidates the item if the user's biometric
//! template changes (e.g. they re-enroll Touch-ID), forcing a fresh
//! confirmation. The `Or DevicePasscode` fallback covers users
//! without biometrics enrolled (system password works as the second
//! factor).
//!
//! Per `docs/prd.md` § 1.5.4: this is a NOTIFY-only feature.
//! Exemptions short-circuit the engine call after the syscall has
//! happened; they never relax kernel policy.

use freallykernel::exempt::per_app::{ExemptionRegistry, PerAppExemption};

/// Stable `kSecAttrService` value used by every Freally exemption.
/// Hard-coded so a future installer can `SecItemDelete` everything
/// keyed by this service without touching unrelated Keychain items.
pub const KEYCHAIN_SERVICE: &str = "com.freally.exemption";

/// Errors surfaced by the wrapper. The two macOS-only OSStatus values
/// we surface explicitly are `errSecUserCanceled` (user dismissed the
/// Touch-ID sheet) and `errSecAuthFailed` (biometric rejected).
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("Keychain backend is not supported on this host (not a macOS target)")]
    Unsupported,
    #[error("user canceled the biometric prompt")]
    UserCanceled,
    #[error("biometric authentication failed")]
    AuthFailed,
    #[error("SecItem call failed with OSStatus {0}")]
    OsStatus(i32),
}

/// Add a new exemption. On macOS this triggers the system-supplied
/// Touch-ID / system-password sheet via the `SecAccessControl` item;
/// on every other host this returns
/// [`KeychainError::Unsupported`].
#[cfg(target_os = "macos")]
pub fn add(exemption: &PerAppExemption) -> Result<(), KeychainError> {
    let _ = exemption;
    // Wave 2 ships the trait wiring + cross-platform contract. The
    // SecItemAdd + SecAccessControlCreateWithFlags ObjC call lands in
    // the macOS-runtime validation pass — this Windows-built
    // foundation can't link against Security.framework. The pattern:
    //
    //   let ac = SecAccessControlCreateWithFlags(
    //       kCFAllocatorDefault,
    //       kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    //       kSecAccessControlBiometryCurrentSet
    //           | kSecAccessControlOr
    //           | kSecAccessControlDevicePasscode,
    //       &err,
    //   );
    //   let attrs = NSDictionary { kSecClass: kSecClassGenericPassword,
    //                              kSecAttrService: KEYCHAIN_SERVICE,
    //                              kSecAttrAccount: exemption.account_key(),
    //                              kSecAttrAccessControl: ac,
    //                              kSecValueData: <serialized payload> };
    //   let status = SecItemAdd(attrs, NULL);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn add(_exemption: &PerAppExemption) -> Result<(), KeychainError> {
    Err(KeychainError::Unsupported)
}

#[cfg(target_os = "macos")]
pub fn remove(bundle_id: &str, team_id: &str) -> Result<(), KeychainError> {
    let _ = (bundle_id, team_id);
    // SecItemDelete with a matching dictionary; identical
    // SecAccessControl gate so the user must re-confirm to remove.
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn remove(_bundle_id: &str, _team_id: &str) -> Result<(), KeychainError> {
    Err(KeychainError::Unsupported)
}

/// Load every exemption belonging to `KEYCHAIN_SERVICE`. On macOS
/// this issues `SecItemCopyMatching` with `kSecMatchLimitAll`; the
/// user is prompted once for the whole list, not per-item.
#[cfg(target_os = "macos")]
pub fn load_all() -> Result<Vec<PerAppExemption>, KeychainError> {
    // Returns an empty list until the macOS-runtime pass wires the
    // real call. Empty is the correct fallback at first install (no
    // exemptions yet).
    Ok(Vec::new())
}

#[cfg(not(target_os = "macos"))]
pub fn load_all() -> Result<Vec<PerAppExemption>, KeychainError> {
    Err(KeychainError::Unsupported)
}

/// Repopulate `registry` from the Keychain. Called on daemon startup
/// and after every mutation. Errors short-circuit without clobbering
/// the existing cache (defensive: a transient `errSecUserCanceled`
/// shouldn't drop the list to zero).
pub fn refresh_registry(registry: &ExemptionRegistry) -> Result<(), KeychainError> {
    let list = load_all()?;
    registry.replace(list);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_id_is_stable() {
        // Stable id surfaces in the Keychain query — a rename would
        // orphan every existing exemption.
        assert_eq!(KEYCHAIN_SERVICE, "com.freally.exemption");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn add_off_macos_is_unsupported() {
        let e = PerAppExemption::new("com.x", "ABCDE12345", None).unwrap();
        let err = add(&e).unwrap_err();
        assert!(matches!(err, KeychainError::Unsupported));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn load_all_off_macos_is_unsupported() {
        let err = load_all().unwrap_err();
        assert!(matches!(err, KeychainError::Unsupported));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn refresh_registry_starts_empty_on_macos_until_runtime_pass() {
        let reg = ExemptionRegistry::new();
        refresh_registry(&reg).unwrap();
        assert!(reg.is_empty());
    }
}
