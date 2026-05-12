// History page (TASK-033).
//
// Table of past scans. Phase 3 ships the basics — sort + multi-select-
// for-diff is Phase 7 (TASK-071).

import type { Component } from "solid-js";
import { Show, createMemo, onMount } from "solid-js";
import { FindingRow } from "@/components/FindingRow";
import { StatusPill } from "@/components/StatusPill";
import {
  historyDetailResource,
  historyListResource,
  refreshHistory,
  selectScan,
  selectedScanId,
} from "@/stores/history";

const History: Component = () => {
  onMount(() => {
    refreshHistory();
  });

  const rows = createMemo(() => historyListResource() ?? []);

  return (
    <div class="flex h-full flex-col gap-4 p-6">
      <header class="flex items-center justify-between">
        <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
          History
        </h1>
        <button
          type="button"
          class="rounded-sm border border-myth-line bg-myth-bg-1 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
          onClick={() => refreshHistory()}
        >
          Refresh
        </button>
      </header>

      <Show
        when={rows().length > 0}
        fallback={
          <div class="rounded-md border border-dashed border-myth-line bg-myth-bg-1 p-6 text-center text-sm text-myth-text-lo">
            No scans yet. Start one from the Scan page.
          </div>
        }
      >
        <section class="overflow-hidden rounded-md border border-myth-line bg-myth-bg-1">
          <table class="w-full">
            <thead class="border-b border-myth-line text-left text-xs uppercase tracking-wide text-myth-text-lo">
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
                  <td class="max-w-xs truncate px-4 py-2 font-mono text-xs text-myth-text-md">
                    {r.target_paths}
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
        <section class="overflow-hidden rounded-md border border-myth-line bg-myth-bg-1">
          <header class="flex items-center justify-between border-b border-myth-line px-4 py-2">
            <h2 class="font-mono text-sm font-semibold text-myth-text-md">
              Scan #{historyDetailResource()!.summary.id} — findings (
              {historyDetailResource()!.findings.length})
            </h2>
            <button
              type="button"
              class="rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-0.5 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
              onClick={() => selectScan(null)}
            >
              Close
            </button>
          </header>
          <Show
            when={historyDetailResource()!.findings.length > 0}
            fallback={
              <div class="px-4 py-3 text-sm text-myth-text-lo">
                No findings for this scan.
              </div>
            }
          >
            {historyDetailResource()!.findings.map((f) => (
              <FindingRow finding={f} />
            ))}
          </Show>
        </section>
      </Show>
    </div>
  );
};

function formatTimestamp(unix: number): string {
  return new Date(unix * 1000).toISOString().replace("T", " ").slice(0, 19);
}

export default History;
