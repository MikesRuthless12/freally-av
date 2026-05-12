//! One-shot Tauri Updater signing-keypair generator (TASK-044).
//!
//! ```sh
//! # Encrypted (recommended) — supply the password as a CLI arg so the run
//! # is non-interactive and CI-reproducible:
//! cargo run --manifest-path scripts/gen-signing-key/Cargo.toml -- --password "my-strong-pass"
//!
//! # Or unencrypted (set TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "" in GH Secrets):
//! cargo run --manifest-path scripts/gen-signing-key/Cargo.toml -- --no-password
//! ```
//!
//! Writes a minisign-compatible keypair to `./private/`:
//!   * `private/myth-updater.key`       — encrypted secret key
//!   * `private/myth-updater.key.pub`   — public key
//!
//! Output to stdout:
//!   * The public-key string to paste into `tauri.conf.json :: plugins.updater.pubkey`.
//!   * The base64-encoded secret-key body to paste into the
//!     `TAURI_SIGNING_PRIVATE_KEY` GitHub Actions secret.
//!   * A reminder to paste the password into `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
//!
//! `private/` is gitignored. **Do not commit anything from it.**

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use minisign::KeyPair;

#[derive(Parser, Debug)]
#[command(
    name = "gen-signing-key",
    about = "Generate a Tauri Updater minisign keypair (TASK-044)."
)]
struct Cli {
    /// Password to encrypt the secret key with. Mutually exclusive with --no-password.
    #[arg(long)]
    password: Option<String>,
    /// Generate an unencrypted secret key (sets GH secret password to empty).
    #[arg(long, conflicts_with = "password")]
    no_password: bool,
    /// Output directory. Defaults to ./private/.
    #[arg(long, default_value = "private")]
    out_dir: PathBuf,
    /// Overwrite existing key files. Off by default so we don't silently
    /// invalidate a deployed pubkey.
    #[arg(long)]
    force: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.password.is_none() && !cli.no_password {
        return Err(
            "must pass either --password <pw> or --no-password (see scripts/gen-signing-key/src/main.rs)"
                .into(),
        );
    }

    fs::create_dir_all(&cli.out_dir)?;
    let pub_path = cli.out_dir.join("myth-updater.key.pub");
    let sec_path = cli.out_dir.join("myth-updater.key");
    if (pub_path.exists() || sec_path.exists()) && !cli.force {
        // Sec-review L2: surface the existing pubkey's first 8 chars so
        // the operator can sanity-check before overwriting. The full
        // body would be too long for a typical terminal line.
        let existing_summary = match fs::read_to_string(&pub_path) {
            Ok(text) => text
                .lines()
                .filter(|l| !l.starts_with("untrusted comment:"))
                .find(|l| !l.is_empty())
                .map(|s| s.chars().take(12).collect::<String>())
                .unwrap_or_else(|| "<unreadable>".into()),
            Err(_) => "<unreadable>".into(),
        };
        return Err(format!(
            "{} already exists (pubkey prefix: {}…). Pass --force to overwrite. \
             This invalidates the existing pubkey for every installed client.",
            pub_path.display(),
            existing_summary
        )
        .into());
    }

    let password_for_keypair = cli.password.clone().filter(|p| !p.is_empty());
    let KeyPair { pk, sk } = KeyPair::generate_encrypted_keypair(password_for_keypair)?;

    let pub_box = pk.to_box()?;
    fs::write(&pub_path, pub_box.to_string())?;

    let sec_box = sk.to_box(None)?;
    fs::write(&sec_path, sec_box.to_string())?;

    // Sec-review L1: lock the secret-key file down to 0600 on Unix so a
    // shared-system collaborator can't read it. Windows ACLs default to
    // "owner only" for files under the user profile, so this is a no-op
    // there.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&sec_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&sec_path, perms)?;
    }

    println!();
    println!("==========================================================");
    println!("  Mythodikal Updater keypair written to {}", cli.out_dir.display());
    println!("==========================================================");
    println!();
    println!("STEP 1 — Public key (paste into apps/mythodikal/src-tauri/tauri.conf.json");
    println!("        :: plugins.updater.pubkey, replacing REPLACE_WITH_PUBKEY_FROM_CARGO_TAURI_SIGNER_GENERATE):");
    println!();
    // Tauri's pubkey field wants the base64 body only, NOT the full
    // minisign text header. Extract it.
    let pubkey_body = pub_box
        .to_string()
        .lines()
        .filter(|l| !l.starts_with("untrusted comment:"))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("");
    println!("{pubkey_body}");
    println!();
    println!("STEP 2 — GitHub repo secrets (Settings → Secrets and variables → Actions):");
    println!();
    println!("  TAURI_SIGNING_PRIVATE_KEY          = (contents of {})", sec_path.display());
    println!("  TAURI_SIGNING_PRIVATE_KEY_PASSWORD = {}",
        if cli.no_password { "(empty string)".to_string() } else { "(the password you passed via --password)".to_string() }
    );
    println!();
    println!("STEP 3 — Back up {} + the password somewhere safe. If you lose them,", sec_path.display());
    println!("        every installed Mythodikal client will refuse future self-updates and");
    println!("        the only recovery is to ship a new public key as part of a forced");
    println!("        full-reinstall release.");
    println!();

    Ok(())
}
