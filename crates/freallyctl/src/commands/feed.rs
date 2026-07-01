//! `freallyctl feed` (TASK-026 / FR-094).
//!
//! Drives the abuse.ch + NSRL feed updaters from `freallykernel::updater`.
//! `feed update` fetches both feeds (abuse.ch via Auth-Key, NSRL from a
//! configured source) and writes the resulting `.bin` files into
//! `<data_dir>/feeds/`. The actual feed locations are constants in the
//! updater modules; per `docs/prd.md` § 1.5 they default to live HTTPS
//! endpoints.

use std::path::PathBuf;

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};
use freallykernel::{
    db,
    updater::{abusech::AbuseChUpdater, nsrl::NsrlSource, nsrl::NsrlUpdater},
};

#[derive(Subcommand)]
pub enum FeedCmd {
    /// Fetch upstream feeds and rebuild the local `.bin` indexes.
    Update(UpdateArgs),
}

#[derive(Args)]
pub struct UpdateArgs {
    /// abuse.ch Auth-Key. Required to pull MalwareBazaar + ThreatFox.
    /// Register a free key at https://auth.abuse.ch/. If omitted, abuse.ch
    /// is skipped with a warning.
    #[arg(long, env = "FREALLY_ABUSECH_AUTH_KEY")]
    abusech_auth_key: Option<String>,

    /// Local NSRL hash dump (TSV, CSV, or one-hash-per-line text). The
    /// updater scans each line for the first 64-char hex SHA-256 run.
    /// Mutually exclusive with --nsrl-url.
    #[arg(long, conflicts_with = "nsrl_url")]
    nsrl_local: Option<PathBuf>,

    /// Remote NSRL hash dump URL (HTTPS only).
    #[arg(long)]
    nsrl_url: Option<String>,

    /// Override the feeds directory (default `<data_dir>/feeds/`).
    #[arg(long)]
    feeds_dir: Option<PathBuf>,
}

pub async fn run(cmd: FeedCmd) -> anyhow::Result<()> {
    match cmd {
        FeedCmd::Update(args) => update(args).await,
    }
}

async fn update(args: UpdateArgs) -> anyhow::Result<()> {
    let feeds_dir = resolve_feeds_dir(args.feeds_dir.clone())?;
    std::fs::create_dir_all(&feeds_dir)
        .with_context(|| format!("create feeds directory at {}", feeds_dir.display()))?;

    let mut ran_anything = false;

    // abuse.ch
    match args.abusech_auth_key {
        Some(key) if !key.trim().is_empty() => {
            ran_anything = true;
            let updater = AbuseChUpdater::new(key, &feeds_dir);
            eprintln!("abuse.ch: fetching MalwareBazaar + ThreatFox...");
            let report = updater
                .update()
                .await
                .map_err(|e| anyhow!("abuse.ch update failed: {e}"))?;
            println!(
                "abuse.ch: malwarebazaar={} threatfox={} merged={} ({:.1?}) -> {}",
                report.malwarebazaar_count,
                report.threatfox_count,
                report.merged_count,
                report.elapsed,
                updater.output_path().display()
            );
        }
        _ => {
            eprintln!(
                "abuse.ch: skipped (no --abusech-auth-key / FREALLY_ABUSECH_AUTH_KEY). \
                 Register a free key at https://auth.abuse.ch/ to enable."
            );
        }
    }

    // NSRL
    let nsrl_source = match (args.nsrl_local, args.nsrl_url) {
        (Some(p), _) => Some(NsrlSource::Local(p)),
        (_, Some(u)) => Some(NsrlSource::Url(u)),
        _ => None,
    };
    match nsrl_source {
        Some(src) => {
            ran_anything = true;
            let updater = NsrlUpdater::new(src.clone(), &feeds_dir);
            eprintln!("nsrl: reading source {src:?}");
            let report = updater
                .update()
                .await
                .map_err(|e| anyhow!("nsrl update failed: {e}"))?;
            println!(
                "nsrl: parsed={} merged={} ({:.1?}) -> {}",
                report.parsed_count,
                report.merged_count,
                report.elapsed,
                updater.output_path().display()
            );
        }
        None => {
            eprintln!("nsrl: skipped (no --nsrl-local <path> or --nsrl-url <url>)");
        }
    }

    if !ran_anything {
        return Err(anyhow!(
            "nothing to do: provide --abusech-auth-key, --nsrl-local <path>, or --nsrl-url <url>"
        ));
    }
    Ok(())
}

fn resolve_feeds_dir(override_path: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p);
    }
    let data_dir = db::default_data_dir().context("resolve default data dir")?;
    Ok(data_dir.join("feeds"))
}
