//! Outlook `.msg` consumer (TASK-271).
//!
//! The on-disk `.msg` format is a Microsoft Compound File container
//! (the same format Office 97-2003 documents use). The CFB walker
//! lives in [`crate::office::cfb`]; this module accepts the named
//! streams it surfaces and projects them into the same
//! [`crate::email::EmlMessage`] shape the `.eml` parser produces so
//! downstream scan code is single-path.
//!
//! ### Stream conventions
//!
//! Outlook stores MAPI properties as streams named
//! `__substg1.0_<TAG><TYPE>`. The handful Freally actually
//! reads:
//!
//! | Property | TAG | Stream name |
//! |---|---|---|
//! | `PR_SUBJECT_W` | `0037` | `__substg1.0_0037001F` |
//! | `PR_BODY_W` | `1000` | `__substg1.0_1000001F` |
//! | `PR_BODY_HTML` | `1013` | `__substg1.0_10130102` |
//! | `PR_SENDER_EMAIL_ADDRESS_W` | `0C1F` | `__substg1.0_0C1F001F` |
//! | `PR_SENT_REPRESENTING_EMAIL_ADDRESS_W` | `0065` | `__substg1.0_0065001F` |
//! | `PR_DISPLAY_TO_W` | `0E04` | `__substg1.0_0E04001F` |
//! | `PR_MESSAGE_DELIVERY_TIME` | `0E06` | `__substg1.0_0E06` (FILETIME) |
//! | `PR_ATTACH_FILENAME_W` | `3704` | `__substg1.0_3704001F` (in attachment storage) |
//! | `PR_ATTACH_DATA_BIN` | `3701` | `__substg1.0_37010102` (in attachment storage) |
//!
//! Attachment streams live inside `__attach_version1.0_<N>`
//! sub-storages numbered from zero. Callers supply them via
//! [`MsgAttachmentStream`].

use serde::{Deserialize, Serialize};

use super::eml::{EmlAttachment, EmlMessage, MimePart};

/// Subset of property streams the engine reads from a `.msg`
/// container. Each field is the raw stream bytes as returned by
/// [`crate::office::cfb`]; this module decodes the UTF-16-LE
/// strings.
#[derive(Debug, Default, Clone)]
pub struct MsgPropertyStreams {
    pub subject_w: Option<Vec<u8>>,
    pub body_w: Option<Vec<u8>>,
    pub body_html: Option<Vec<u8>>,
    pub sender_email_w: Option<Vec<u8>>,
    pub display_to_w: Option<Vec<u8>>,
    pub attachments: Vec<MsgAttachmentStream>,
}

#[derive(Debug, Default, Clone)]
pub struct MsgAttachmentStream {
    pub filename_w: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
    /// `application/octet-stream` if the .msg didn't carry an
    /// explicit MIME type.
    pub content_type: Option<String>,
}

/// Project a [`MsgPropertyStreams`] bundle into an [`EmlMessage`]
/// so downstream scan flow doesn't branch on container format.
pub fn parse_msg_streams(streams: MsgPropertyStreams) -> EmlMessage {
    let subject = streams.subject_w.as_deref().map(decode_utf16_le);
    let from = streams.sender_email_w.as_deref().map(decode_utf16_le);
    let to = streams.display_to_w.as_deref().map(decode_utf16_le);

    let mut parts = Vec::new();
    if let Some(body) = streams.body_w.as_deref() {
        let text = decode_utf16_le(body);
        parts.push(MimePart {
            content_type: "text/plain".to_string(),
            charset: Some("utf-8".to_string()),
            body: text.into_bytes(),
        });
    }
    if let Some(html) = &streams.body_html {
        // PR_BODY_HTML is already 8-bit CP1252 by spec.
        parts.push(MimePart {
            content_type: "text/html".to_string(),
            charset: None,
            body: html.clone(),
        });
    }

    let mut attachments = Vec::new();
    for att in streams.attachments {
        let filename = att.filename_w.as_deref().map(decode_utf16_le);
        attachments.push(EmlAttachment {
            filename,
            content_type: att
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string()),
            decoded_bytes: att.data.unwrap_or_default(),
        });
    }

    EmlMessage {
        from,
        to,
        subject,
        parts,
        attachments,
        ..Default::default()
    }
}

fn decode_utf16_le(bytes: &[u8]) -> String {
    let mut chars: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let code = u16::from_le_bytes([pair[0], pair[1]]);
        chars.push(code);
    }
    // Trim trailing NULs (Outlook pads).
    while let Some(&0) = chars.last() {
        chars.pop();
    }
    String::from_utf16_lossy(&chars)
}

/// Convenience helper: re-export to keep the `office::cfb` shape
/// addressable by name. Always returns the well-known property
/// tag → stream-name suffix mapping in stable order so feature
/// flags (TASK-275 encrypted-doc fingerprint, TASK-272 macro
/// extractor) can dispatch on the same constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsgPropertyTag {
    SubjectW,
    BodyW,
    BodyHtml,
    SenderEmailW,
    DisplayToW,
    AttachFilenameW,
    AttachDataBin,
}

impl MsgPropertyTag {
    pub fn stream_suffix(self) -> &'static str {
        match self {
            MsgPropertyTag::SubjectW => "0037001F",
            MsgPropertyTag::BodyW => "1000001F",
            MsgPropertyTag::BodyHtml => "10130102",
            MsgPropertyTag::SenderEmailW => "0C1F001F",
            MsgPropertyTag::DisplayToW => "0E04001F",
            MsgPropertyTag::AttachFilenameW => "3704001F",
            MsgPropertyTag::AttachDataBin => "37010102",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for code in s.encode_utf16() {
            out.extend_from_slice(&code.to_le_bytes());
        }
        out
    }

    #[test]
    fn projects_streams_into_eml_shape() {
        let streams = MsgPropertyStreams {
            subject_w: Some(utf16("Status report")),
            body_w: Some(utf16("Hello team")),
            sender_email_w: Some(utf16("boss@example.com")),
            display_to_w: Some(utf16("team@example.com")),
            attachments: vec![MsgAttachmentStream {
                filename_w: Some(utf16("invoice.pdf")),
                data: Some(b"%PDF-1.5 stub".to_vec()),
                content_type: Some("application/pdf".to_string()),
            }],
            ..Default::default()
        };
        let msg = parse_msg_streams(streams);
        assert_eq!(msg.subject.as_deref(), Some("Status report"));
        assert_eq!(msg.from.as_deref(), Some("boss@example.com"));
        assert_eq!(msg.to.as_deref(), Some("team@example.com"));
        assert_eq!(msg.parts.len(), 1);
        assert_eq!(msg.parts[0].content_type, "text/plain");
        assert!(String::from_utf8_lossy(&msg.parts[0].body).contains("Hello team"));
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].filename.as_deref(), Some("invoice.pdf"));
        assert_eq!(msg.attachments[0].content_type, "application/pdf");
    }

    #[test]
    fn body_html_kept_as_8bit() {
        let streams = MsgPropertyStreams {
            body_html: Some(b"<html><body>hi</body></html>".to_vec()),
            ..Default::default()
        };
        let msg = parse_msg_streams(streams);
        assert_eq!(msg.parts.len(), 1);
        assert_eq!(msg.parts[0].content_type, "text/html");
        assert_eq!(msg.parts[0].body, b"<html><body>hi</body></html>");
    }

    #[test]
    fn empty_streams_yield_default_message() {
        let msg = parse_msg_streams(MsgPropertyStreams::default());
        assert!(msg.subject.is_none());
        assert!(msg.from.is_none());
        assert!(msg.parts.is_empty());
        assert!(msg.attachments.is_empty());
    }

    #[test]
    fn trailing_null_terminator_is_stripped() {
        let mut bytes = utf16("with nul");
        bytes.push(0);
        bytes.push(0);
        let streams = MsgPropertyStreams {
            subject_w: Some(bytes),
            ..Default::default()
        };
        let msg = parse_msg_streams(streams);
        assert_eq!(msg.subject.as_deref(), Some("with nul"));
    }

    #[test]
    fn property_tag_suffixes_are_stable() {
        assert_eq!(MsgPropertyTag::SubjectW.stream_suffix(), "0037001F");
        assert_eq!(MsgPropertyTag::AttachDataBin.stream_suffix(), "37010102");
    }
}
