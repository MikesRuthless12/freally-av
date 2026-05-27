//! TASK-225 — Entropy heatmap per file.
//!
//! Computes Shannon entropy in bits per byte over a sliding window.
//! High-entropy regions are characteristic of compressed or encrypted
//! data — packers, archives, encrypted payloads, polyglot dropper
//! stubs. The detector surfaces a per-window heatmap and an overall
//! summary; downstream policies (TASK-217 packer ID, TASK-228 per-
//! extension scan) decide what to do with the signal.
//!
//! No external dep — pure Rust, allocation-light: one fixed
//! `[u32; 256]` histogram per window, no per-byte heap.

/// Default sliding-window size for the heatmap. 4 KiB matches the
/// typical packed-stub granularity (entropy spikes inside one PE
/// section); smaller windows surface false positives on legitimate
/// short compressed regions (PNG IDAT, zlib stream prefix).
pub const DEFAULT_WINDOW_BYTES: usize = 4096;

/// Threshold above which a window counts as "high entropy" in the
/// summary. 7.5 bits/byte is the conservative line used in published
/// malware-triage literature for distinguishing packed/encrypted from
/// English text or x86/ARM code. (English text: ~4.5 bpb; native
/// code: ~6.0 bpb; lzma compressed: ~7.8 bpb; AES output: ~7.99 bpb.)
pub const DEFAULT_HIGH_ENTROPY_BITS: f32 = 7.5;

/// Compute Shannon entropy over `window`, in bits per byte.
/// Returns 0.0 for an empty input.
pub fn shannon_entropy_bpb(window: &[u8]) -> f32 {
    if window.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in window {
        freq[b as usize] += 1;
    }
    let n = window.len() as f32;
    let mut h = 0.0f32;
    for &f in freq.iter() {
        if f == 0 {
            continue;
        }
        let p = (f as f32) / n;
        h -= p * p.log2();
    }
    h
}

/// One row of the heatmap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyWindow {
    pub offset: usize,
    pub len: usize,
    pub entropy_bpb: f32,
}

/// Heatmap + summary for an entire byte stream.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyReport {
    pub windows: Vec<EntropyWindow>,
    /// Mean entropy across all non-empty windows.
    pub mean_bpb: f32,
    /// Highest single-window entropy observed.
    pub max_bpb: f32,
    /// Fraction of windows above [`DEFAULT_HIGH_ENTROPY_BITS`].
    pub high_window_fraction: f32,
}

/// Scan `bytes` with non-overlapping windows of `window_size`; return
/// a per-window heatmap + summary. Final partial window is included.
pub fn entropy_heatmap(bytes: &[u8], window_size: usize) -> EntropyReport {
    let win = window_size.max(1);
    let mut windows = Vec::with_capacity(bytes.len().div_ceil(win));
    let mut sum = 0.0f32;
    let mut max = 0.0f32;
    let mut high = 0usize;
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + win).min(bytes.len());
        let w = &bytes[offset..end];
        let h = shannon_entropy_bpb(w);
        if h > max {
            max = h;
        }
        if h >= DEFAULT_HIGH_ENTROPY_BITS {
            high += 1;
        }
        sum += h;
        windows.push(EntropyWindow {
            offset,
            len: w.len(),
            entropy_bpb: h,
        });
        offset = end;
    }
    let n = windows.len().max(1);
    EntropyReport {
        mean_bpb: sum / (n as f32),
        max_bpb: max,
        high_window_fraction: (high as f32) / (n as f32),
        windows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bytes_zero_entropy() {
        assert_eq!(shannon_entropy_bpb(&[]), 0.0);
        // A single repeating byte yields zero entropy (one symbol).
        assert_eq!(shannon_entropy_bpb(&[0u8; 1024]), 0.0);
    }

    #[test]
    fn uniform_distribution_yields_8bpb() {
        // 256 distinct byte values, each appearing once → log2(256) = 8.
        let buf: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy_bpb(&buf);
        assert!((h - 8.0).abs() < 0.01, "expected ~8.0 got {h}");
    }

    #[test]
    fn english_text_low_entropy_around_4() {
        let s = b"the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog. the quick brown fox.";
        let h = shannon_entropy_bpb(s);
        assert!(
            h > 3.5 && h < 5.0,
            "english-text entropy should sit around 4-4.5 bpb, got {h}"
        );
    }

    #[test]
    fn heatmap_summarises_high_entropy_run() {
        // First half all zeros (entropy = 0), second half uniform
        // 0..255 cycling (entropy ≈ 8). Half the windows should be
        // high-entropy.
        let mut buf = vec![0u8; 4096];
        let high: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        buf.extend(high);
        let rep = entropy_heatmap(&buf, 1024);
        assert!(rep.windows.len() >= 6);
        // Mean should be roughly between 0 and 8; max should be near 8.
        assert!(
            rep.max_bpb > 7.5,
            "max should be high-entropy, got {}",
            rep.max_bpb
        );
        assert!(rep.mean_bpb > 2.0 && rep.mean_bpb < 7.0);
        assert!(rep.high_window_fraction > 0.0);
    }

    #[test]
    fn small_window_uses_partial_tail() {
        let buf = vec![0u8; 100];
        let rep = entropy_heatmap(&buf, 30);
        // 100 / 30 = 3 full windows + 1 partial.
        assert_eq!(rep.windows.len(), 4);
        assert_eq!(rep.windows[0].len, 30);
        assert_eq!(rep.windows.last().unwrap().len, 10);
    }
}
