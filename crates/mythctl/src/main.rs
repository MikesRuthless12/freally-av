//! Mythodikal Anti-Virus command-line interface (`mythctl`).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

mod commands;

#[derive(Parser)]
#[command(
    name = "mythctl",
    about = "Mythodikal Anti-Virus command-line interface",
    version,
    long_about = None,
)]
struct Cli {
    /// Override the SQLite database path. Defaults to
    /// `<data_dir>/mythodikal.db` per PRD § 3.
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a scan against the given path. Progress streams to stderr;
    /// results stream to stdout (text by default, NDJSON with `--format json`).
    Scan {
        /// Path to scan (file or directory).
        path: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Compute SHA-256 alongside BLAKE3 for every file (slower).
        #[arg(long)]
        sha256: bool,

        /// Follow symbolic links during traversal.
        #[arg(long)]
        follow_symlinks: bool,
    },

    /// Manage the quarantine vault. List, restore, delete, and bulk ops
    /// per FR-041..047.
    Quarantine {
        #[command(subcommand)]
        sub: commands::quarantine::QuarantineCmd,
    },

    /// Manage signature feeds. `feed update` pulls abuse.ch + NSRL and
    /// rebuilds the local `.bin` indexes per FR-094.
    Feed {
        #[command(subcommand)]
        sub: commands::feed::FeedCmd,
    },

    /// Toggle the real-time Shields master kill-switch (FR-160).
    /// `mythctl shields {on,off,status,pause <minutes>}`.
    Shields {
        #[command(subcommand)]
        sub: commands::shields::ShieldsCmd,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Format {
    /// Human-readable text summary.
    Text,
    /// One JSON object per line (NDJSON) for each scan event.
    Json,
}

fn main() -> anyhow::Result<()> {
    // Stream engine tracing to stderr so operators can diagnose walker
    // fallback paths (NTFS MFT vs PosixWalker), USN journal rotation,
    // and feed-update progress directly from the CLI. Honors `MYTH_LOG`
    // (e.g. `MYTH_LOG=info,mythkernel::walker=debug`) and falls back to
    // INFO when unset. `try_init()` is a no-op if a subscriber is
    // already installed (some integration tests pre-install one).
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MYTH_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        match cli.command {
            Commands::Scan {
                path,
                format,
                sha256,
                follow_symlinks,
            } => commands::scan::run(path, format, sha256, follow_symlinks).await,
            Commands::Quarantine { sub } => commands::quarantine::run(sub, cli.db.clone()),
            Commands::Feed { sub } => commands::feed::run(sub).await,
            Commands::Shields { sub } => commands::shields::run(sub, None),
        }
    })
}
