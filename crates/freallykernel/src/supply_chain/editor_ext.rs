//! Editor-extension scanner + publisher allowlist
//! (TASK-310, TASK-311).
//!
//! Two-part foundation:
//!
//!   * [`enumerate`] walks VS Code (`~/.vscode/extensions/`,
//!     `~/.vscode-server/extensions/`) and JetBrains
//!     (`<plugins-root>/<plugin>/META-INF/plugin.xml`).
//!   * [`classify`] joins each extension against the bundled
//!     publisher allowlist; anything outside the allowlist
//!     surfaces as `unverified-publisher`.
//!
//! YARA-X over each extension's JS / `plugin.xml` body runs at
//! Wave closeout via the existing `detect::yara_engine`
//! consumer; this module records the manifest path so the
//! closeout pass can re-read on demand.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditorFamily {
    VsCode,
    JetBrains,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditorExtension {
    pub family: EditorFamily,
    pub publisher: Option<String>,
    pub identifier: String,
    pub version: Option<String>,
    pub manifest_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherClassification {
    Allowlisted,
    UnverifiedPublisher,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedExtension {
    pub extension: EditorExtension,
    pub classification: PublisherClassification,
}

/// Bundled allowlist of trusted publishers. Conservative on
/// purpose — first-party platform vendors and a handful of
/// long-standing ecosystem maintainers. Users add per-project
/// publishers in the UI settings table.
pub const BUNDLED_PUBLISHER_ALLOWLIST: &[&str] = &[
    "Microsoft",
    "ms-python",
    "ms-vscode",
    "ms-azuretools",
    "ms-vscode-remote",
    "ms-toolsai",
    "vscode",
    "JetBrains",
    "redhat",
    "rust-lang",
    "golang",
    "Anthropic",
    "GitHub",
    "Vue",
    "EditorConfig",
    "esbenp",
    "dbaeumer",
];

/// Enumerate both VS Code and JetBrains extension roots.
///
/// `vscode_roots` should include every `~/.vscode/extensions/`
/// / `~/.vscode-server/extensions/` the host carries.
/// `jetbrains_plugin_roots` covers
/// `~/Library/Application Support/JetBrains/<IDE>/plugins/`
/// (macOS), `%APPDATA%\JetBrains\<IDE>\plugins\` (Windows), and
/// `~/.local/share/JetBrains/<IDE>/plugins/` (Linux).
pub fn enumerate(
    vscode_roots: &[PathBuf],
    jetbrains_plugin_roots: &[PathBuf],
) -> Vec<EditorExtension> {
    let mut out = Vec::new();
    for root in vscode_roots {
        enumerate_vscode(root, &mut out);
    }
    for root in jetbrains_plugin_roots {
        enumerate_jetbrains(root, &mut out);
    }
    out
}

fn enumerate_vscode(root: &Path, out: &mut Vec<EditorExtension>) {
    let Ok(read) = std::fs::read_dir(root) else {
        return;
    };
    for entry in read.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let manifest = dir.join("package.json");
        let Ok(body) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
            continue;
        };
        let publisher = json
            .get("publisher")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let name = json
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = json
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let identifier = match publisher.as_ref() {
            Some(p) if !p.is_empty() => format!("{p}.{name}"),
            _ => name.clone(),
        };
        if identifier.is_empty() {
            continue;
        }
        out.push(EditorExtension {
            family: EditorFamily::VsCode,
            publisher,
            identifier,
            version,
            manifest_path: manifest,
        });
    }
}

fn enumerate_jetbrains(root: &Path, out: &mut Vec<EditorExtension>) {
    let Ok(read) = std::fs::read_dir(root) else {
        return;
    };
    for entry in read.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        // JetBrains plugins live as `<plugin>/lib/<jar>` with
        // metadata embedded in `META-INF/plugin.xml`. Many
        // plugins also extract a top-level `META-INF/plugin.xml`
        // for the layout we record here.
        let manifest = dir.join("META-INF").join("plugin.xml");
        if !manifest.exists() {
            // Record the plugin dir anyway so YARA-X can still
            // scan it at closeout; identifier defaults to the
            // directory name.
            out.push(EditorExtension {
                family: EditorFamily::JetBrains,
                publisher: None,
                identifier: dir
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string(),
                version: None,
                manifest_path: dir.clone(),
            });
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let identifier = extract_xml_tag(&body, "id")
            .or_else(|| extract_xml_tag(&body, "name"))
            .unwrap_or_else(|| {
                dir.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string()
            });
        let publisher = extract_xml_tag(&body, "vendor");
        let version = extract_xml_tag(&body, "version");
        out.push(EditorExtension {
            family: EditorFamily::JetBrains,
            publisher,
            identifier,
            version,
            manifest_path: manifest,
        });
    }
}

fn extract_xml_tag(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut search_from = 0usize;
    loop {
        let rel = body[search_from..].find(&open)?;
        let open_idx = search_from + rel;
        // Confirm the byte after `<tag` is `>` or whitespace — i.e.
        // we matched `<id` and not `<idea-plugin`.
        let after_pos = open_idx + open.len();
        let next = body.as_bytes().get(after_pos).copied();
        let ok = matches!(next, Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'/'));
        if !ok {
            search_from = open_idx + open.len();
            continue;
        }
        let after_open = &body[after_pos..];
        let gt = after_open.find('>')?;
        // Self-closing element (`<tag .../>`) — skip and continue
        // hunting for a real `<tag>...</tag>` pair later in the
        // document.
        let opener_bytes = &after_open.as_bytes()[..gt];
        if opener_bytes.last() == Some(&b'/') {
            search_from = after_pos + gt + 1;
            continue;
        }
        let inner_start = after_pos + gt + 1;
        let Some(close_idx) = body[inner_start..].find(&close) else {
            // Advance past this opener and keep hunting; a later
            // occurrence may have a matching close.
            search_from = inner_start;
            continue;
        };
        let inner = &body[inner_start..inner_start + close_idx];
        let trimmed = inner.trim();
        if trimmed.is_empty() {
            search_from = inner_start + close_idx + close.len();
            continue;
        }
        return Some(trimmed.to_string());
    }
}

/// Classify one extension against the bundled allowlist (plus
/// any user-added publishers the caller passes in `user_allowlist`).
pub fn classify(extension: &EditorExtension, user_allowlist: &[String]) -> ClassifiedExtension {
    let publisher = extension.publisher.as_deref().unwrap_or("");
    let bundled = BUNDLED_PUBLISHER_ALLOWLIST
        .iter()
        .any(|p| p.eq_ignore_ascii_case(publisher));
    let user = user_allowlist
        .iter()
        .any(|p| p.eq_ignore_ascii_case(publisher));
    let classification = if bundled || user {
        PublisherClassification::Allowlisted
    } else {
        PublisherClassification::UnverifiedPublisher
    };
    ClassifiedExtension {
        extension: extension.clone(),
        classification,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn vscode_enumeration_reads_publisher() {
        let dir = tempdir().unwrap();
        let ext = dir.path().join("ms-python.python-2024.0.0");
        std::fs::create_dir_all(&ext).unwrap();
        std::fs::write(
            ext.join("package.json"),
            r#"{"publisher":"ms-python","name":"python","version":"2024.0.0"}"#,
        )
        .unwrap();
        let out = enumerate(&[dir.path().to_path_buf()], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].publisher.as_deref(), Some("ms-python"));
        assert_eq!(out[0].identifier, "ms-python.python");
    }

    #[test]
    fn jetbrains_enumeration_parses_plugin_xml() {
        let dir = tempdir().unwrap();
        let plug = dir.path().join("my-plugin");
        std::fs::create_dir_all(plug.join("META-INF")).unwrap();
        std::fs::write(
            plug.join("META-INF/plugin.xml"),
            r#"
<idea-plugin>
    <id>com.example.plugin</id>
    <name>Example</name>
    <vendor>JetBrains</vendor>
    <version>1.2.3</version>
</idea-plugin>
"#,
        )
        .unwrap();
        let out = enumerate(&[], &[dir.path().to_path_buf()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].family, EditorFamily::JetBrains);
        assert_eq!(out[0].identifier, "com.example.plugin");
        assert_eq!(out[0].publisher.as_deref(), Some("JetBrains"));
        assert_eq!(out[0].version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn xml_extractor_skips_self_closing_to_find_real_tag() {
        let dir = tempdir().unwrap();
        let plug = dir.path().join("plug-with-self-close");
        std::fs::create_dir_all(plug.join("META-INF")).unwrap();
        std::fs::write(
            plug.join("META-INF/plugin.xml"),
            r#"
<idea-plugin>
    <id>com.x</id>
    <vendor email="x@example.com"/>
    <vendor>Real Vendor</vendor>
</idea-plugin>
"#,
        )
        .unwrap();
        let out = enumerate(&[], &[dir.path().to_path_buf()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].publisher.as_deref(), Some("Real Vendor"));
    }

    #[test]
    fn classify_allowlisted_publisher_is_allowlisted() {
        let ext = EditorExtension {
            family: EditorFamily::VsCode,
            publisher: Some("Microsoft".to_string()),
            identifier: "ms.foo".to_string(),
            version: Some("1.0".to_string()),
            manifest_path: PathBuf::new(),
        };
        let c = classify(&ext, &[]);
        assert_eq!(c.classification, PublisherClassification::Allowlisted);
    }

    #[test]
    fn classify_user_allowlist_overrides_default() {
        let ext = EditorExtension {
            family: EditorFamily::VsCode,
            publisher: Some("acme-corp".to_string()),
            identifier: "acme.foo".to_string(),
            version: None,
            manifest_path: PathBuf::new(),
        };
        let default = classify(&ext, &[]);
        assert_eq!(
            default.classification,
            PublisherClassification::UnverifiedPublisher
        );
        let user = classify(&ext, &["acme-corp".to_string()]);
        assert_eq!(user.classification, PublisherClassification::Allowlisted);
    }

    #[test]
    fn missing_publisher_marks_unverified() {
        let ext = EditorExtension {
            family: EditorFamily::VsCode,
            publisher: None,
            identifier: "lone".to_string(),
            version: None,
            manifest_path: PathBuf::new(),
        };
        let c = classify(&ext, &[]);
        assert_eq!(
            c.classification,
            PublisherClassification::UnverifiedPublisher
        );
    }
}
