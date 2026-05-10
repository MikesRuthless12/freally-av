//! Mythodikal Anti-Virus command-line interface (`mythctl`).
//!
//! Phase 0 / TASK-004 ships an empty CLI shell. Subcommands are added by
//! TASK-017 (scan), TASK-026 (quarantine, feed), TASK-156 (shields),
//! TASK-157 (autostart), TASK-158 (tray helpers).

use clap::Parser;

mod commands;

#[derive(Parser)]
#[command(
    name = "mythctl",
    about = "Mythodikal Anti-Virus command-line interface",
    version,
    long_about = None,
)]
struct Cli {}

fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();
    Ok(())
}
