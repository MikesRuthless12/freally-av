//! `freallyd-macos` daemon entry point (Phase 9 scaffold).
//!
//! Wave-1 mac real-time (FSEvents listener + opportunistic ESF NOTIFY)
//! ships in Phase 9 (TASK-079/080/081). The binary entry exists at
//! this Phase-8 boundary so the cross-platform USB stack lands on
//! macOS without a workspace re-org in the next phase.

use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "freallyd", version)]
struct Cli {
    #[arg(long)]
    once: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    info!("freallyd-macos scaffold ready; FSEvents + ESF NOTIFY land in Phase 9");
    if cli.once {
        return Ok(());
    }
    Ok(())
}
