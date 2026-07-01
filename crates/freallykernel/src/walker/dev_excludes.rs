//! TASK-205 + TASK-206 — Dev-tuned exclude preset + project-root detection.
//!
//! Two related concerns share this module:
//!
//! - **TASK-205 (hot-path skip-list)**: a bundled starter pack of
//!   well-known noisy directories (`node_modules/`, `target/`,
//!   `.cargo/`, package caches). Ships **disabled** so installations
//!   are pristine until the user opts in; the UI surfaces them as
//!   suggestions via [`bundled_dev_excludes`].
//! - **TASK-206 (project-aware preset)**: [`detect_project_root`]
//!   walks ancestors from a candidate path looking for one of a fixed
//!   set of project-root markers (`.git`, `Cargo.toml`, `pnpm-lock.yaml`,
//!   etc.). When found, the engine can scope the bundled dev preset to
//!   THAT subtree only (no global accidental scope creep).
//!
//! No DB schema here — the dev preset is in-tree static data; the
//! per-scan project-root cache lives on the worker context. Future UI
//! `Settings → Excludes` writes accepted suggestions into the existing
//! `exclusions` table (Phase 4 / TASK-042) so they persist.

use std::path::{Path, PathBuf};

/// Static starter pack — paths most users want excluded but few will
/// remember to add manually. Each entry is a glob suffix; the caller
/// pairs it with a project-root prefix (TASK-206) or applies it
/// globally (TASK-205).
///
/// All entries ship **disabled** in `Settings → Excludes` until the
/// user accepts the suggestion. The list is intentionally short — every
/// entry should be defensible as "high-write, machine-regenerable, low
/// security value to scan." Adding entries should be a deliberate
/// decision, not a vibes-based dump.
pub const BUNDLED_DEV_EXCLUDES: &[&str] = &[
    "node_modules",
    "target",
    ".cargo/registry",
    ".cargo/git",
    "vendor", // Go / Composer / Rails
    ".gradle",
    ".m2",
    ".cache",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".pnpm-store",
    ".yarn/cache",
    ".turbo",
];

/// Returns the bundled dev-exclude starter pack. UI consumes this to
/// render the "suggested excludes" surface (TASK-205).
pub fn bundled_dev_excludes() -> &'static [&'static str] {
    BUNDLED_DEV_EXCLUDES
}

/// Project-root markers. Detected by [`detect_project_root`] when
/// walking up from a candidate path; presence of any of these in a
/// directory marks that directory as a project root.
///
/// Ordered most-specific first so a polyglot repo's `Cargo.toml`
/// inside a Node monorepo classifies the inner project as Rust rather
/// than capturing the outer `package.json` as the same project.
const PROJECT_MARKERS: &[&str] = &[
    "Cargo.toml",
    "go.mod",
    "pyproject.toml",
    "pnpm-lock.yaml",
    "yarn.lock",
    "package.json",
    "Gemfile",
    "composer.json",
    "build.gradle",
    "build.gradle.kts",
    "pom.xml",
    "Package.swift",
    "Project.toml",
    "mix.exs",
    "stack.yaml",
    ".git",
];

/// The kind of project a directory belongs to, derived from which
/// marker matched first. Lets the engine apply a kind-specific subset
/// of the bundled dev excludes when desired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectKind {
    Rust,
    Go,
    Python,
    Node,
    Ruby,
    Php,
    Java,
    Swift,
    Julia,
    Elixir,
    Haskell,
    GenericGit,
    Unknown,
}

impl ProjectKind {
    fn from_marker(marker: &str) -> Self {
        match marker {
            "Cargo.toml" => Self::Rust,
            "go.mod" => Self::Go,
            "pyproject.toml" => Self::Python,
            "pnpm-lock.yaml" | "yarn.lock" | "package.json" => Self::Node,
            "Gemfile" => Self::Ruby,
            "composer.json" => Self::Php,
            "build.gradle" | "build.gradle.kts" | "pom.xml" => Self::Java,
            "Package.swift" => Self::Swift,
            "Project.toml" => Self::Julia,
            "mix.exs" => Self::Elixir,
            "stack.yaml" => Self::Haskell,
            ".git" => Self::GenericGit,
            _ => Self::Unknown,
        }
    }
}

/// Result of walking up from a candidate path looking for a project
/// root marker. The `root` is the directory that owns the marker; the
/// `kind` lets the engine pick a kind-specific exclude bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRoot {
    pub root: PathBuf,
    pub kind: ProjectKind,
}

/// Walk up from `start` looking for a directory containing any of
/// [`PROJECT_MARKERS`]. Returns the **deepest** matching ancestor (so
/// nested project roots — a Rust crate inside a Node monorepo — are
/// classified by the inner marker, not the outer).
///
/// `start` is treated as a directory if it points to one, otherwise
/// its parent is the search start (so passing a file path Just Works).
pub fn detect_project_root(start: &Path) -> Option<ProjectRoot> {
    let mut cursor: Option<&Path> = if start.is_dir() {
        Some(start)
    } else {
        start.parent()
    };
    while let Some(dir) = cursor {
        for marker in PROJECT_MARKERS {
            if dir.join(marker).exists() {
                return Some(ProjectRoot {
                    root: dir.to_path_buf(),
                    kind: ProjectKind::from_marker(marker),
                });
            }
        }
        cursor = dir.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn bundled_set_is_non_empty_and_unique() {
        let pack = bundled_dev_excludes();
        assert!(pack.len() >= 10);
        let mut sorted: Vec<&str> = pack.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            pack.len(),
            "duplicate entries in bundled pack"
        );
    }

    #[test]
    fn detects_rust_project_root() {
        let td = tempdir().unwrap();
        let proj = td.path().join("crates").join("my-crate");
        let src = proj.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(proj.join("Cargo.toml"), b"[package]\nname = \"x\"").unwrap();
        fs::write(src.join("lib.rs"), b"").unwrap();

        let pr = detect_project_root(&src.join("lib.rs")).unwrap();
        assert_eq!(pr.root, proj);
        assert_eq!(pr.kind, ProjectKind::Rust);
    }

    #[test]
    fn returns_none_outside_any_project() {
        let td = tempdir().unwrap();
        let lone = td.path().join("loose.txt");
        fs::write(&lone, b"hi").unwrap();
        // No markers anywhere up the tree → None.
        assert!(detect_project_root(&lone).is_none());
    }

    #[test]
    fn nested_project_returns_innermost() {
        // outer is a Node project; inner is a Rust crate; a file deep
        // inside the inner crate should resolve to the Rust root, not
        // the Node monorepo.
        let td = tempdir().unwrap();
        let outer = td.path().join("monorepo");
        let inner = outer.join("crates").join("inner");
        let inner_src = inner.join("src");
        fs::create_dir_all(&inner_src).unwrap();
        fs::write(outer.join("package.json"), b"{}").unwrap();
        fs::write(inner.join("Cargo.toml"), b"[package]\nname=\"i\"").unwrap();
        fs::write(inner_src.join("lib.rs"), b"").unwrap();
        let pr = detect_project_root(&inner_src.join("lib.rs")).unwrap();
        assert_eq!(pr.root, inner, "innermost project wins");
        assert_eq!(pr.kind, ProjectKind::Rust);
    }

    #[test]
    fn directory_input_works() {
        // Caller may pass a directory rather than a file inside it.
        let td = tempdir().unwrap();
        fs::write(td.path().join("pyproject.toml"), b"").unwrap();
        let pr = detect_project_root(td.path()).unwrap();
        assert_eq!(pr.kind, ProjectKind::Python);
    }

    #[test]
    fn git_marker_classifies_as_generic_git() {
        let td = tempdir().unwrap();
        fs::create_dir_all(td.path().join(".git")).unwrap();
        let pr = detect_project_root(td.path()).unwrap();
        assert_eq!(pr.kind, ProjectKind::GenericGit);
    }
}
