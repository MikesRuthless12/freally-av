# Mythodikal Brand Assets

Single source of truth for the Mythodikal Anti-Virus mark and wordmark.

## Files

| File | Purpose |
|---|---|
| `m-glyph.svg` | The "M" glyph used as the app icon, the favicon, and the tray icon base. 256 × 256 viewBox; baby-blue gradient with light highlight, bottom shade, and a soft drop shadow for a 3D effect. Transparent background. |
| `wordmark.svg` | "M" glyph + "Mythodikal Anti-Virus" in Inter Display 600. Used in the marketing site, the splash screen, and About. 720 × 144 viewBox. |

## Visual identity

The mark is a geometric uppercase **M** built from rectangular and diagonal strokes meeting at sharp angles. The fill uses a top-left → bottom-right linear gradient running from light baby blue (`#C9EAFB`) through baby blue (`#89CFF0`) to a darker baby blue (`#3F8FBF`), with a subtle stroke at `#2A6A8E`. A top-edge highlight gradient and a bottom shade gradient give it depth, and a soft drop shadow plants it against dark backgrounds.

## Usage rules

- **Preserve the geometry.** The M is built from rectangular and diagonal strokes meeting at sharp angles — do not adjust proportions, rotate, or skew.
- **Preserve the palette.** The baby-blue gradient + highlight + shade + drop shadow are the canonical look. Do not flatten to a single color or recolor.
- **Transparent background.** Never composite the M against a solid background tile in the icon itself; let host backgrounds show through.
- **Minimum size:** 16 px for the glyph, 96 px wide for the wordmark. Below 16 px, the gradient is mostly invisible; that's expected.
- **Clear-space:** at least `0.5 × M-height` of padding on all sides.
- **Do not** apply additional drop shadows, glows, bevels, or animations on top of the existing 3D treatment.

## Tray icon variants

Per `docs/prd.md` § 6.12 (FR-162) and TASK-158, the tray icon has four states with priority `shields_off > update_available > scanning > idle`. Variants live under `apps/mythodikal/src-tauri/icons/`:

- `tray-{idle,scanning,shields_off,update_available}-{16,22,32}.png` — full-color, the M with a small overlay glyph in the bottom-right (accent dot for scanning; `!` on a `--myth-bad` chip for shields_off; `↑` on a `--myth-warn` chip for update_available; idle is the bare M).
- `tray-{idle,scanning,shields_off,update_available}-mac-22.png` — single-channel alpha templates for macOS menu bars (`isTemplate = true`). Status color signaling on macOS is conveyed by the menu-item label, not by the icon.

The base mark in each variant is rendered from `m-glyph.svg` so the M's geometry stays consistent.

## License

The brand assets are part of Mythodikal Anti-Virus and governed by `LICENSE.md` (proprietary, source-visible). Section 3.9 prohibits use of the marks without separate written permission.
