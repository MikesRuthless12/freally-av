//! `mythctl shields` (TASK-156).
//!
//! `mythctl shields {on,off,status,pause <minutes>}` per FR-160.7. The
//! CLI talks directly to the engine's [`ShieldsBroker`] file — no
//! Tauri IPC required — so administrators / scripts can flip the
//! kill-switch on a headless box where the GUI never launched.

use std::path::PathBuf;

use anyhow::{Context, anyhow};
use clap::Subcommand;
use mythkernel::{
    db,
    realtime::shields::{ShieldsActor, ShieldsBroker},
};

use crate::Format;

#[derive(Subcommand)]
pub enum ShieldsCmd {
    /// Turn shields ON (default state).
    On,
    /// Turn shields OFF until explicitly re-enabled.
    Off,
    /// Pause shields for N minutes (auto-resumes after).
    Pause {
        /// Minutes to pause for. Must be > 0.
        minutes: u32,
    },
    /// Show current state.
    Status {
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

pub fn run(cmd: ShieldsCmd, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let data_dir = match data_dir {
        Some(p) => p,
        None => db::default_data_dir().context("resolve default data dir")?,
    };
    let broker = ShieldsBroker::open(&data_dir).map_err(|e| anyhow!("open shields: {e}"))?;

    match cmd {
        ShieldsCmd::On => {
            let next = broker
                .set(true, None, ShieldsActor::Cli)
                .map_err(|e| anyhow!(e))?;
            println!("shields ON (was: {})", short(&broker.get()));
            print_state(&next);
        }
        ShieldsCmd::Off => {
            let next = broker
                .set(false, None, ShieldsActor::Cli)
                .map_err(|e| anyhow!(e))?;
            println!("shields OFF (until re-enabled)");
            print_state(&next);
        }
        ShieldsCmd::Pause { minutes } => {
            let next = broker
                .set(false, Some(minutes), ShieldsActor::Cli)
                .map_err(|e| anyhow!(e))?;
            println!("shields paused for {minutes} minutes");
            print_state(&next);
        }
        ShieldsCmd::Status { format } => {
            let state = broker.get();
            match format {
                Format::Json => println!("{}", serde_json::to_string(&state)?),
                Format::Text => print_state(&state),
            }
        }
    }
    Ok(())
}

fn print_state(state: &mythkernel::realtime::shields::ShieldsState) {
    if state.enabled {
        println!("  enabled: true");
    } else {
        match state.pause_until_utc {
            Some(t) => println!("  enabled: false (paused until unix={t})"),
            None => println!("  enabled: false (indefinite)"),
        }
    }
}

fn short(state: &mythkernel::realtime::shields::ShieldsState) -> &'static str {
    if state.enabled {
        "ON"
    } else if state.pause_until_utc.is_some() {
        "PAUSED"
    } else {
        "OFF"
    }
}
