//! `.gitignore`-aware scan toggle (TASK-313).
//!
//! Pure-Rust pattern filter. The roadmap target wires a future
//! `WalkOpts::honor_gitignore` flag into [`super::posix`] — this
//! foundation owns the pattern matcher and the per-root rule
//! aggregation so the walker integration becomes a thin tie-in.
//!
//! Pattern grammar we support (subset of `man 5 gitignore`):
//!
//!   * blank lines / `#` comments — ignored
//!   * leading `/` — pattern is rooted at the `.gitignore` dir
//!   * trailing `/` — directory-only match
//!   * `!pattern` — negate (re-include)
//!   * `*` — zero-or-more non-separator chars
//!   * `?` — exactly one non-separator char
//!   * `**` — zero-or-more path segments
//!
//! Not yet supported: character classes (`[abc]`). Rare in
//! real `.gitignore`s; tracked as a follow-up.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitignoreRule {
    /// Root directory the rule applies to (the directory the
    /// `.gitignore` lived in).
    pub root: PathBuf,
    pub pattern: String,
    pub negated: bool,
    pub directory_only: bool,
    pub anchored: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitignoreFilter {
    pub rules: Vec<GitignoreRule>,
}

impl GitignoreFilter {
    /// Parse one `.gitignore` body. `root` is the directory the
    /// file lived in.
    pub fn from_text(root: &Path, body: &str) -> Self {
        let mut rules = Vec::new();
        for raw in body.lines() {
            let line = raw.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (negated, rest) = if let Some(stripped) = line.strip_prefix('!') {
                (true, stripped)
            } else {
                (false, line)
            };
            let (anchored, rest) = if let Some(stripped) = rest.strip_prefix('/') {
                (true, stripped)
            } else {
                (false, rest)
            };
            let (directory_only, rest) = if let Some(stripped) = rest.strip_suffix('/') {
                (true, stripped)
            } else {
                (false, rest)
            };
            if rest.is_empty() {
                continue;
            }
            rules.push(GitignoreRule {
                root: root.to_path_buf(),
                pattern: rest.to_string(),
                negated,
                directory_only,
                anchored,
            });
        }
        GitignoreFilter { rules }
    }

    /// Concatenate two filters; later rules override earlier
    /// (matches git's last-match-wins semantics).
    pub fn extend(&mut self, other: GitignoreFilter) {
        self.rules.extend(other.rules);
    }

    /// Does any rule ignore `path`?
    ///
    /// `is_dir` flips on directory-only patterns. The walker
    /// invokes this once per file *and* once per directory it
    /// considers descending into.
    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        let mut decision = false;
        for rule in &self.rules {
            if rule.directory_only && !is_dir {
                continue;
            }
            let Ok(rel) = path.strip_prefix(&rule.root) else {
                continue;
            };
            if matches_pattern(rel, &rule.pattern, rule.anchored) {
                decision = !rule.negated;
            }
        }
        decision
    }
}

fn matches_pattern(rel: &Path, pattern: &str, anchored: bool) -> bool {
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    if anchored {
        glob_match(&rel_str, pattern)
    } else {
        // Unanchored: pattern can match any suffix segment.
        for (i, _) in rel_str.match_indices('/') {
            if glob_match(&rel_str[i + 1..], pattern) {
                return true;
            }
        }
        glob_match(&rel_str, pattern)
    }
}

fn glob_match(input: &str, pattern: &str) -> bool {
    // Iterative glob matcher with `*`, `?`, and `**`.
    let inp = input.as_bytes();
    let pat = pattern.as_bytes();
    let mut i = 0usize;
    let mut j = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;
    let mut double_star = false;
    while i < inp.len() {
        if j < pat.len() {
            let pc = pat[j];
            // Detect `**` once we see consecutive `*`.
            if pc == b'*' {
                if j + 1 < pat.len() && pat[j + 1] == b'*' {
                    double_star = true;
                    j += 2;
                    if j < pat.len() && pat[j] == b'/' {
                        j += 1;
                    }
                    star_idx = Some(j);
                    match_idx = i;
                    continue;
                } else {
                    double_star = false;
                    j += 1;
                    star_idx = Some(j);
                    match_idx = i;
                    continue;
                }
            }
            if pc == b'?' && inp[i] != b'/' {
                i += 1;
                j += 1;
                continue;
            }
            if pc == inp[i] {
                i += 1;
                j += 1;
                continue;
            }
        }
        if let Some(si) = star_idx {
            if !double_star && inp[match_idx] == b'/' {
                return false;
            }
            j = si;
            match_idx += 1;
            i = match_idx;
        } else {
            return false;
        }
    }
    while j < pat.len() && pat[j] == b'*' {
        j += 1;
    }
    j == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_simple_file_pattern() {
        let f = GitignoreFilter::from_text(Path::new("/proj"), "*.log\n");
        assert!(f.is_ignored(Path::new("/proj/x.log"), false));
        assert!(f.is_ignored(Path::new("/proj/sub/x.log"), false));
        assert!(!f.is_ignored(Path::new("/proj/x.txt"), false));
    }

    #[test]
    fn anchored_pattern_does_not_match_subdirs() {
        let f = GitignoreFilter::from_text(Path::new("/proj"), "/build\n");
        assert!(f.is_ignored(Path::new("/proj/build"), true));
        assert!(!f.is_ignored(Path::new("/proj/sub/build"), true));
    }

    #[test]
    fn directory_only_pattern() {
        let f = GitignoreFilter::from_text(Path::new("/proj"), "target/\n");
        assert!(f.is_ignored(Path::new("/proj/target"), true));
        assert!(!f.is_ignored(Path::new("/proj/target"), false));
    }

    #[test]
    fn double_star_matches_any_depth() {
        let f = GitignoreFilter::from_text(Path::new("/p"), "**/cache\n");
        assert!(f.is_ignored(Path::new("/p/a/b/cache"), true));
        assert!(f.is_ignored(Path::new("/p/cache"), true));
    }

    #[test]
    fn negation_re_includes() {
        let f = GitignoreFilter::from_text(Path::new("/proj"), "*.log\n!keep.log\n");
        assert!(f.is_ignored(Path::new("/proj/x.log"), false));
        assert!(!f.is_ignored(Path::new("/proj/keep.log"), false));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let f = GitignoreFilter::from_text(Path::new("/proj"), "# comment\n\n*.tmp\n");
        assert_eq!(f.rules.len(), 1);
        assert_eq!(f.rules[0].pattern, "*.tmp");
    }
}
