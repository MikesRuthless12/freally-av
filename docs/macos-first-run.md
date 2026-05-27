# macOS first-run: opening an unsigned Mythodikal bundle

Mythodikal Anti-Virus ships **unsigned and unnotarized** on macOS. Per the
project's zero-cost / no-paid-vendor-program constraint, we do not enroll in
the paid Apple Developer Program ($99 / yr) and therefore cannot:

- Use Apple's `notarytool` (notarization gate)
- Embed an Apple Developer ID code-signing identity in the bundle
- Request entitlements that are restricted to Developer Program members
  (Endpoint Security, etc.)

This means Gatekeeper — the macOS service that vets app provenance on first
launch — will refuse to run the bundle the normal way (double-click in
Finder). This page documents the one-time workaround.

## What you'll see on first launch

Double-clicking `Mythodikal Anti-Virus.app` (or a freshly mounted
`.dmg`) the first time produces one of two dialogs depending on your
macOS version:

- macOS 13 (Ventura) and earlier:
  `"Mythodikal Anti-Virus" can't be opened because it is from an unidentified developer.`
- macOS 14 (Sonoma) and later:
  `"Mythodikal Anti-Virus" cannot be opened because Apple cannot check it for malicious software.`

Both messages are Gatekeeper enforcing its default "signed-and-notarized
only" policy.

## One-time unlock (right-click → Open)

1. Locate the `Mythodikal Anti-Virus.app` bundle (either in `/Applications`
   after copying from the DMG, or wherever you placed it).
2. **Right-click** (or `Control`-click) the bundle and choose **Open** from
   the context menu.
3. The Gatekeeper dialog now offers an `Open` button alongside the usual
   `Move to Bin` / `Cancel`. Click `Open`.
4. macOS records your override and the bundle launches normally on every
   subsequent run — no need to repeat the right-click after the first
   acceptance.

If `Open` is not offered (you can only Cancel), open `System Settings →
Privacy & Security`, scroll to the **Security** section, find the recent
`"Mythodikal Anti-Virus" was blocked from use because it is not from an
identified developer.` line, and click **Open Anyway**.

## Why this is safe to do

Gatekeeper's check is **provenance**, not malware analysis: it asks "did
Apple's developer registry sign this?" and refuses if the answer is no.
Apple does not analyze your particular bundle. Many legitimate open-source
tools ship this way (e.g., older versions of OBS, every Homebrew cask
formula that doesn't paid-sign, etc.).

For independent verification of the bundle you downloaded, Mythodikal
provides two integrity signals you can check before bypassing Gatekeeper:

1. **Tauri Updater ed25519 signature.** Every release asset is signed
   with our ed25519 key. The public half is compiled into the app and
   listed in `apps/mythodikal/src-tauri/tauri.conf.json` under
   `plugins.updater.pubkey`. Verify locally with `minisign`:
   ```sh
   minisign -V -p <our-pubkey> -m Mythodikal\ Anti-Virus.app.tar.gz
   ```
2. **Optional Sigstore manifest.** When attached to a release, the
   manifest documents the GitHub Actions build provenance for the
   bundle. Verify with `cosign verify-blob` against our OIDC issuer.

Both signals are advisory on macOS (the OS does not natively verify
Tauri or Sigstore signatures); they exist for users who want to confirm
the binary matches what the public GitHub release pipeline produced.

## What we still do for hardening

Even though the bundle is unsigned, the Tauri build sets a set of
"free" hardened-runtime entitlements on the binary as metadata
(`apps/mythodikal/src-tauri/entitlements.plist`):

- No JIT (`com.apple.security.cs.allow-jit = false`)
- No unsigned-executable memory
- No dyld environment-variable injection
- Library validation stays on (yara-x is pure Rust and does not need
  unsigned-library loading)
- Executable page protection stays on

These attributes are advisory on an unsigned bundle but document the
intended security posture and become enforced if a downstream consumer
ever notarizes a fork on their own dime.

## Why we cannot pay to fix this

Per `docs/prd.md` § 1.5.3, the project is committed to shipping at $0 / yr
for both maintainer and end users. The Apple Developer Program is a
$99 / yr recurring cost per Apple's terms, and accepting it would violate
the constraint. If a future sponsor covers the $99 unconditionally, the
project may revisit; that is a Phase 13 (donor / Pro tier) decision and
not on the v0.19.84 stable path.
