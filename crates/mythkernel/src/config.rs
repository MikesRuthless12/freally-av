//! TOML configuration loader.
//!
//! TASK-016 (Phase 1) — reads `<config_dir>/config.toml`. Missing file or
//! missing keys fall back to the baked-in [`Config::default`]. Per FR-110,
//! `telemetry.enabled` defaults to **false** and is never silently flipped on.
//!
//! Phase 4 (TASK-156) extends `general` with the close-action and tray
//! toggles; Phase 4 (TASK-039) extends `scanning` with adaptive throttle
//! caps. Each phase adds its own fields with sane defaults; older configs
//! continue to load.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::EngineError;

/// Top-level config. Every nested struct derives `Default` so a brand-new
/// install gets the engineer-vetted defaults without touching disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: General,
    pub scanning: Scanning,
    pub telemetry: Telemetry,
    pub realtime: Realtime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    /// Theme: `"dark"` (default) or `"light"`.
    pub theme: String,
    /// UI language code (`"en-US"`, …).
    pub language: String,
    /// `MinimizeToTray` (default) or `Quit`. See FR-162.6.
    pub close_action: String,
}

impl Default for General {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
            language: "en-US".into(),
            close_action: "MinimizeToTray".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Scanning {
    /// Static worker count for the cross-platform walker. `0` = auto
    /// (`available_parallelism / 2`).
    pub workers: usize,
    /// Honor symbolic links (default `false` per FR-007).
    pub follow_symlinks: bool,
    /// Compute SHA-256 lazily alongside BLAKE3 (default `false` per FR-009).
    pub compute_sha256: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Telemetry {
    /// Always **false** by default. See FR-110.
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Realtime {
    /// Shields master switch baseline. Persisted authoritatively in
    /// `<data_dir>/shields.json` (TASK-156); the value here is only read on
    /// first run.
    pub shields_enabled: bool,
}

impl Default for Realtime {
    fn default() -> Self {
        Self {
            shields_enabled: true,
        }
    }
}

/// Resolve the canonical config path: `<config_dir>/config.toml`.
pub fn default_config_path() -> Result<PathBuf, EngineError> {
    let dirs = directories::ProjectDirs::from("com", "Mythodikal", "Mythodikal")
        .ok_or_else(|| EngineError::Config("no platform config dir".into()))?;
    let dir = dirs.config_dir().to_path_buf();
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("config.toml"))
}

/// Load config from `path`. A missing file is **not** an error — defaults are
/// returned. Parse errors are surfaced.
pub fn load(path: &Path) -> Result<Config, EngineError> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&text)
        .map_err(|e| EngineError::Config(format!("parse {}: {e}", path.display())))?;
    Ok(cfg)
}

/// Persist config to `path`. Atomically: write to `path.tmp` and rename.
pub fn save(path: &Path, cfg: &Config) -> Result<(), EngineError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let serialized =
        toml::to_string_pretty(cfg).map_err(|e| EngineError::Config(format!("serialize: {e}")))?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, serialized)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn defaults_have_telemetry_off() {
        let cfg = Config::default();
        assert!(!cfg.telemetry.enabled, "FR-110: telemetry off by default");
        assert_eq!(cfg.general.theme, "dark");
        assert_eq!(cfg.general.close_action, "MinimizeToTray");
        assert!(cfg.realtime.shields_enabled, "shields default ON");
    }

    #[test]
    fn missing_file_returns_defaults() {
        let dir = tempdir().unwrap();
        let cfg = load(&dir.path().join("does-not-exist.toml")).unwrap();
        assert!(!cfg.telemetry.enabled);
    }

    #[test]
    fn round_trip_keeps_values() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config.toml");
        let mut cfg = Config::default();
        cfg.general.language = "fr-FR".into();
        cfg.scanning.compute_sha256 = true;
        save(&p, &cfg).unwrap();
        let loaded = load(&p).unwrap();
        assert_eq!(loaded.general.language, "fr-FR");
        assert!(loaded.scanning.compute_sha256);
    }

    #[test]
    fn partial_config_fills_with_defaults() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config.toml");
        std::fs::write(&p, "[general]\ntheme = \"light\"\n").unwrap();
        let cfg = load(&p).unwrap();
        assert_eq!(cfg.general.theme, "light");
        // Untouched sections still use defaults.
        assert!(!cfg.telemetry.enabled);
        assert_eq!(cfg.general.close_action, "MinimizeToTray");
    }
}
