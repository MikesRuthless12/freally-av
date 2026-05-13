// History page (TASK-033).
//
// Table of past scans + drill-down detail panel for findings. Phase 6
// adds per-row action buttons, bulk actions (quarantine/delete/ignore
// every finding in this scan), a confirm-first dialog, and a
// split-pane layout so the table + detail both fit in the viewport.

import { ask } from "@tauri-apps/plugin-dialog";
import type { Component } from "solid-js";
import { Show, createMemo, createSignal, onMount } from "solid-js";
import { FindingRow } from "@/components/FindingRow";
import { displayPath } from "@/components/PathDisplay";
import { StatusPill } from "@/components/StatusPill";
import { findingAction, historyClear } from "@/ipc/invoke";
import type { FindingAction, FindingView } from "@/ipc/types";
import {
  historyDetailResource,
  historyListResource,
  refreshHistory,
  selectScan,
  selectedScanId,
  updateDetailFindingAction,
} from "@/stores/history";

const History: Component = () => {
  onMount(() => {
    refreshHistory();
  });

  const rows = createMemo(() => historyListResource() ?? []);
  const [clearing, setClearing] = createSignal(false);
  const [busyAction, setBusyAction] = createSignal<number | null>(null);
  const [bulkAction, setBulkAction] = createSignal<FindingAction | null>(null);
  const [bulkProgress, setBulkProgress] = createSignal<{ done: number; total: number } | null>(null);
  const [actionError, setActionError] = createSignal<string | null>(null);

  /// Clear every scan + finding from the DB. Quarantine vault is
  /// untouched. Prompts a confirm-first dialog because there's no
  /// undo path.
  const onClearHistory = async () => {
    if (rows().length === 0) return;
    const confirmed = await ask(
      `Clear all ${rows().length} scan${rows().length === 1 ? "" : "s"} from history? This also resets the verdict cache so the next scan re-hashes every file from scratch. Quarantined files are NOT removed.`,
      {
        title: "Clear history",
        kind: "warning",
        okLabel: "Yes",
        cancelLabel: "No",
      },
    );
    if (!confirmed) return;
    setClearing(true);
    setActionError(null);
    try {
      await historyClear();
      selectScan(null);
      refreshHistory();
    } catch (err) {
      setActionError(String(err));
    } finally {
      setClearing(false);
    }
  };

  /// Per-row action. After the IPC succeeds we patch the loaded
  /// detail's finding in place (no re-fetch, no panel re-render) so
  /// the user's scroll position stays put.
  const onFindingAction = async (f: FindingView, action: FindingAction) => {
    setBusyAction(f.id);
    setActionError(null);
    try {
      await findingAction(f.id, action);
      // Translate the action verb into the resulting `action_taken`
      // pill state. Mirrors the backend's `findings.action_taken`
      // transition table.
      const newState =
        action === "quarantine"
          ? "quarantined"
          : action === "restore"
            ? "restored"
            : action; // delete | ignore → same string in DB
      updateDetailFindingAction(f.id, newState);
    } catch (err) {
      setActionError(String(err));
    } finally {
      setBusyAction(null);
    }
  };

  /// Bulk action — confirms first, then iterates every finding in
  /// the currently-loaded detail and fires the per-row IPC. The
  /// `bulkAction` signal both disables the buttons during the run
  /// and drives the live progress label.
  const onBulkAction = async (action: FindingAction) => {
    const detail = historyDetailResource();
    if (!detail || detail.findings.length === 0) return;
    // Only apply to rows that haven't already received this action.
    const targets = detail.findings.filter((f) => {
      if (action === "quarantine") return f.action_taken === "none";
      if (action === "delete") return f.action_taken !== "deleted";
      if (action === "ignore") return f.action_taken !== "ignored";
      if (action === "restore") return f.action_taken === "quarantined";
      return true;
    });
    if (targets.length === 0) return;
    const confirmed = await ask(
      `${action.charAt(0).toUpperCase() + action.slice(1)} all ${targets.length} finding${targets.length === 1 ? "" : "s"} in this scan?`,
      {
        title: `Bulk ${action}`,
        kind: action === "delete" ? "warning" : "info",
        okLabel: "Yes",
        cancelLabel: "No",
      },
    );
    if (!confirmed) return;
    setBulkAction(action);
    setActionError(null);
    setBulkProgress({ done: 0, total: targets.length });
    let done = 0;
    let firstErr: string | null = null;
    for (const f of targets) {
      try {
        await findingAction(f.id, action);
        const newState =
          action === "quarantine"
            ? "quarantined"
            : action === "restore"
              ? "restored"
              : action;
        updateDetailFindingAction(f.id, newState);
      } catch (err) {
        if (firstErr === null) firstErr = String(err);
      }
      done += 1;
      setBulkProgress({ done, total: targets.length });
    }
    if (firstErr) setActionError(firstErr);
    setBulkAction(null);
    setBulkProgress(null);
  };

  return (
    <div class="flex h-full flex-col gap-4 p-6">
      <header class="flex items-center justify-between">
        <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
          History
        </h1>
        <div class="flex gap-2">
          <button
            type="button"
            class="rounded-sm border border-myth-line bg-myth-bg-1 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
            onClick={() => refreshHistory()}
          >
            Refresh
          </button>
          <Show when={rows().length > 0}>
            <button
              type="button"
              class="rounded-sm border border-myth-bad/60 bg-myth-bg-1 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-bad hover:bg-myth-bad/10 disabled:cursor-not-allowed disabled:opacity-50"
              disabled={clearing()}
              onClick={onClearHistory}
            >
              {clearing() ? "Clearing…" : "Clear history"}
            </button>
          </Show>
        </div>
      </header>

      <Show
        when={rows().length > 0}
        fallback={
          <div class="rounded-md border border-dashed border-myth-line bg-myth-bg-1 p-6 text-center text-sm text-myth-text-lo">
            No scans yet. Start one from the Scan page.
          </div>
        }
      >
        {/* Scan list — cap at ~40 vh so the detail panel below can
            occupy the remaining viewport without the page becoming
            two scrollbars deep. */}
        <section class="max-h-[40vh] overflow-y-auto rounded-md border border-myth-line bg-myth-bg-1">
          <table class="w-full">
            <thead class="sticky top-0 z-10 border-b border-myth-line bg-myth-bg-1 text-left text-xs uppercase tracking-wide text-myth-text-lo">
              <tr>
                <th class="px-4 py-2 font-medium">ID</th>
                <th class="px-4 py-2 font-medium">Started</th>
                <th class="px-4 py-2 font-medium">Target</th>
                <th class="px-4 py-2 font-medium text-right">Files</th>
                <th class="px-4 py-2 font-medium text-right">Findings</th>
                <th class="px-4 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows().map((r) => (
                <tr
                  class={`cursor-pointer border-b border-myth-line/50 last:border-b-0 hover:bg-myth-bg-2 ${selectedScanId() === r.id ? "bg-myth-bg-2" : ""}`}
                  onClick={() => selectScan(r.id)}
                >
                  <td class="px-4 py-2 font-mono text-xs tabular-nums text-myth-text-md">
                    {r.id}
                  </td>
                  <td class="px-4 py-2 font-mono text-xs tabular-nums text-myth-text-md">
                    {formatTimestamp(r.started_at_utc)}
                  </td>
                  <td
                    class="max-w-xs truncate px-4 py-2 font-mono text-xs text-myth-text-md"
                    title={formatTargets(r.target_paths)}
                  >
                    {formatTargets(r.target_paths)}
                  </td>
                  <td class="px-4 py-2 text-right font-mono text-xs tabular-nums text-myth-text-md">
                    {r.files_visited.toLocaleString("en-US")}
                  </td>
                  <td class="px-4 py-2 text-right font-mono text-xs tabular-nums text-myth-text-md">
                    {r.findings_count.toLocaleString("en-US")}
                  </td>
                  <td class="px-4 py-2">
                    <StatusPill status={r.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </Show>

      <Show when={historyDetailResource()}>
        {/* Detail panel — `flex-1` so it fills the remaining viewport
            height left over after the (capped) scan-list table. */}
        <section class="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-myth-line bg-myth-bg-1">
          <header class="flex flex-wrap items-center justify-between gap-2 border-b border-myth-line px-4 py-2">
            <h2 class="font-mono text-sm font-semibold text-myth-text-md">
              Scan #{historyDetailResource()!.summary.id} — findings (
              {historyDetailResource()!.findings.length})
              <Show when={bulkProgress()}>
                <span class="ml-2 text-myth-text-lo">
                  · {bulkAction()} {bulkProgress()!.done} / {bulkProgress()!.total}
                </span>
              </Show>
            </h2>
            <div class="flex flex-wrap items-center gap-1">
              {/* Bulk action buttons. Disabled while another bulk run
                  is in flight; each prompts a Yes/No dialog before
                  doing N round-trips. */}
              <Show when={historyDetailResource()!.findings.length > 0}>
                <button
                  type="button"
                  class="rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-0.5 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50"
                  disabled={bulkAction() !== null}
                  onClick={() => onBulkAction("quarantine")}
                >
                  Quarantine all
                </button>
                <button
                  type="button"
                  class="rounded-sm border border-myth-bad/60 bg-myth-bg-1 px-2 py-0.5 font-mono text-xs uppercase tracking-wide text-myth-bad hover:bg-myth-bad/10 disabled:cursor-not-allowed disabled:opacity-50"
                  disabled={bulkAction() !== null}
                  onClick={() => onBulkAction("delete")}
                >
                  Delete all
                </button>
                <button
                  type="button"
                  class="rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-0.5 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50"
                  disabled={bulkAction() !== null}
                  onClick={() => onBulkAction("ignore")}
                >
                  Ignore all
                </button>
              </Show>
              <button
                type="button"
                class="rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-0.5 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
                onClick={() => selectScan(null)}
              >
                Close
              </button>
            </div>
          </header>
          <Show
            when={historyDetailResource()!.findings.length > 0}
            fallback={
              <div class="px-4 py-3 text-sm text-myth-text-lo">
                No findings for this scan.
              </div>
            }
          >
            <div class="flex-1 overflow-y-auto">
              {historyDetailResource()!.findings.map((f) => (
                <FindingRow
                  finding={f}
                  busy={busyAction() === f.id || bulkAction() !== null}
                  onAction={(a) => onFindingAction(f, a)}
                />
              ))}
            </div>
            <Show when={actionError()}>
              <div class="border-t border-myth-bad/50 bg-myth-bad/10 px-4 py-2 font-mono text-xs text-myth-bad">
                {actionError()}
              </div>
            </Show>
          </Show>
        </section>
      </Show>
    </div>
  );
};

function formatTimestamp(unix: number): string {
  return new Date(unix * 1000).toISOString().replace("T", " ").slice(0, 19);
}

/** Parse the JSON-encoded `target_paths` column and render the array
 *  as a comma-joined list with the Windows extended-length prefix
 *  (`\\?\`) stripped. Falls back to the raw string on parse failure
 *  so a corrupt row doesn't break the entire list. */
function formatTargets(raw: string): string {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.map((p) => displayPath(String(p))).join(", ");
    }
  } catch {
    // fall through
  }
  return displayPath(raw);
}

export default History;
