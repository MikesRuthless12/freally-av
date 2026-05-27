// FindingRow (TASK-031, extended TASK-191 + TASK-196).
//
// One row in the findings list shown on the Scan dashboard + History
// detail. Severity-coloured pill + path + rule + match-strength
// tooltip + citation-copy + action menu (the menu is wired but
// action handling is owned by the parent so a single row stays
// decoupled from the store).

import type { Component } from "solid-js";
import { Show } from "solid-js";
import type { FindingAction, FindingView } from "@/ipc/types";
import { PathDisplay } from "./PathDisplay";
import { StatusPill } from "./StatusPill";

interface Props {
  finding: FindingView;
  onAction?: (action: FindingAction) => void;
  /** Disable action buttons (e.g. while a previous action is in flight). */
  busy?: boolean;
}

/**
 * TASK-191 — Confidence-graded findings.
 *
 * Map the per-finding `match_strength` returned by the dual-key gate
 * (`crates/mythkernel/src/detect/dual_key_gate.rs`) to a four-tier
 * confidence label rendered as a small pill next to the severity.
 *
 *   * gold_multihash  → P0 (both BLAKE3 + SHA-256 matched the same row)
 *   * gold_single     → P1 (single-hash match against gold-tier)
 *   * silver          → P1 (silver-tier row, md5 or sha256 only)
 *   * partial         → P2 (TASK-180 prefix match, full hash pending)
 *
 * Quick-Action defaults shift per confidence in `Scan.tsx` (P0 →
 * quarantine, P3 → notify only). The pill is informational only —
 * the colour matches the underlying severity but a tooltip explains
 * the dual-key reasoning so the user understands the confidence.
 */
function confidenceLabel(matchStrength: string | null | undefined): {
  pri: string;
  tooltip: string;
} {
  switch (matchStrength) {
    case "gold_multihash":
      return {
        pri: "P0",
        tooltip:
          "Highest confidence: both BLAKE3 and SHA-256 matched the same blacklist row. Default action: quarantine.",
      };
    case "gold_single":
      return {
        pri: "P1",
        tooltip:
          "Single-hash match against a gold-tier blacklist row. Dual-key confirmation unavailable; verify before auto-action.",
      };
    case "silver":
      return {
        pri: "P1",
        tooltip:
          "Silver-tier match (md5 or sha256 only — no BLAKE3 cross-confirmation). Severity downgraded one notch; verify before quarantine.",
      };
    case "partial":
      return {
        pri: "P2",
        tooltip:
          "Partial-match prefix hit on a large file. Full-file hash pending to confirm or refute.",
      };
    default:
      return {
        pri: "P1",
        tooltip: "Standard confidence (no match-strength metadata).",
      };
  }
}

/**
 * TASK-196 — Per-finding source-citation copy button.
 *
 * Emits a Markdown footnote block the user can paste directly into
 * a report:
 *
 * ```
 * - **Rule:** abusech:hash:0123abcd…
 * - **Source:** abuse.ch MalwareBazaar
 * - **Path:** /path/to/file.exe
 * - **Severity:** high
 * - **Observed:** 2026-05-23T22:34:56Z
 * ```
 *
 * Clipboard-only; no network call. Uses the browser Clipboard API
 * (available in Tauri's WebView2 + WKWebView + WebKitGTK alike).
 */
function citationFor(finding: FindingView): string {
  const observed = new Date().toISOString();
  return [
    `- **Rule:** ${finding.rule_id}`,
    `- **Source:** ${finding.rule_source}`,
    `- **Path:** ${finding.path}`,
    `- **Severity:** ${finding.severity}`,
    `- **Observed:** ${observed}`,
  ].join("\n");
}

async function copyCitation(finding: FindingView): Promise<void> {
  try {
    await navigator.clipboard.writeText(citationFor(finding));
  } catch {
    // Tauri's WebView clipboard write should always succeed; if it
    // doesn't (e.g. permission denied in dev), fall back silently —
    // the user can still copy the rendered finding row text manually.
  }
}

export const FindingRow: Component<Props> = (props) => {
  const conf = () =>
    confidenceLabel((props.finding as unknown as { match_strength?: string }).match_strength);
  return (
    <div class="flex items-start gap-4 border-b border-myth-line px-4 py-2 last:border-b-0">
      <StatusPill status={props.finding.severity} />
      <span
        class="rounded-sm border border-myth-line bg-myth-bg-0 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-myth-text-md"
        title={conf().tooltip}
      >
        {conf().pri}
      </span>
      <div class="flex-1 min-w-0">
        <PathDisplay path={props.finding.path} />
        <div class="mt-0.5 font-mono text-xs text-myth-text-lo">
          {props.finding.rule_source}: {props.finding.rule_id}
        </div>
      </div>
      <button
        type="button"
        class="rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
        title="Copy a Markdown citation block to the clipboard"
        onClick={() => void copyCitation(props.finding)}
      >
        Cite
      </button>
      <StatusPill status={props.finding.action_taken} />
      <Show when={props.onAction}>
        <ActionMenu
          state={props.finding.action_taken}
          busy={props.busy}
          onAction={(a) => props.onAction?.(a)}
        />
      </Show>
    </div>
  );
};

const ActionMenu: Component<{
  state: string;
  busy?: boolean;
  onAction: (action: FindingAction) => void;
}> = (props) => {
  const allowed = (): FindingAction[] => {
    switch (props.state) {
      case "none":
        return ["quarantine", "delete", "ignore"];
      case "quarantined":
        return ["restore", "delete", "ignore"];
      default:
        return [];
    }
  };
  return (
    <div class="flex gap-1">
      {allowed().map((action) => (
        <button
          type="button"
          class="rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-0.5 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50"
          disabled={props.busy}
          onClick={() => props.onAction(action)}
        >
          {action}
        </button>
      ))}
    </div>
  );
};
