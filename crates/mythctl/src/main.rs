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
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Format {
    /// Human-readable text summary.
    Text,
    /// One JSON object per line (NDJSON) for each scan event.
    Json,
}

fn main() -> anyhow::Result<()> {
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
        }
    })
}
