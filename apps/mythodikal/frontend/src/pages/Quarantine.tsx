// Quarantine page (TASK-034).
//
// Lists every quarantined file with checkboxes for multi-select. Bulk
// ops surface the same FR-046 typed-DELETE gate the CLI uses
// (--confirm), reified here as a "type DELETE to enable" input.

import type { Component } from "solid-js";
import { Show, createMemo, createSignal, onMount } from "solid-js";
import {
  quarantineDelete,
  quarantineDeleteAll,
  quarantineDeleteMany,
  quarantineRestore,
  quarantineRestoreAll,
  quarantineRestoreMany,
} from "@/ipc/invoke";
import type { BatchOpReport, QuarantineId, QuarantineItem } from "@/ipc/types";
import { PathDisplay } from "@/components/PathDisplay";
import { ProgressBar } from "@/components/ProgressBar";
import {
  attachQuarantineEvents,
  clearSelection,
  currentBatchProgress,
  quarantineListResource,
  refreshQuarantine,
  selectedQuarantineIds,
  toggleSelected,
} from "@/stores/quarantine";

const Quarantine: Component = () => {
  const [busy, setBusy] = createSignal(false);
  const [lastError, setLastError] = createSignal<string | null>(null);
  const [confirmText, setConfirmText] = createSignal("");
  const [lastReport, setLastReport] = createSignal<BatchOpReport | null>(null);

  onMount(() => {
    attachQuarantineEvents();
    refreshQuarantine();
  });

  const items = createMemo<QuarantineItem[]>(
    () => quarantineListResource() ?? [],
  );

  const selectedCount = () => selectedQuarantineIds().size;

  const wrap = async <T,>(op: () => Promise<T>): Promise<T | null> => {
    setBusy(true);
    setLastError(null);
    setLastReport(null);
    try {
      const result = await op();
      refreshQuarantine();
      clearSelection();
      return result;
    } catch (err) {
      setLastError(String(err));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const onRestoreSingle = (id: QuarantineId) =>
    wrap(() => quarantineRestore(id));

  const onDeleteSingle = (id: QuarantineId) =>
    wrap(() => quarantineDelete(id));

  const onRestoreSelected = async () => {
    const r = await wrap(() =>
      quarantineRestoreMany(Array.from(selectedQuarantineIds())),
    );
    if (r) setLastReport(r);
  };

  const onDeleteSelected = async () => {
    const r = await wrap(() =>
      quarantineDeleteMany(Array.from(selectedQuarantineIds())),
    );
    if (r) setLastReport(r);
  };

  const onRestoreAll = async () => {
    const r = await wrap(() => quarantineRestoreAll());
    if (r) setLastReport(r);
  };

  const onDeleteAll = async () => {
    if (confirmText() !== "DELETE") {
      setLastError(
        "Type DELETE to confirm. Bulk delete is irreversible (FR-046).",
      );
      return;
    }
    const r = await wrap(() => quarantineDeleteAll(true));
    if (r) setLastReport(r);
    setConfirmText("");
  };

  return (
    <div class="flex h-full flex-col gap-4 p-6">
      <header class="flex items-center justify-between">
        <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
          Quarantine
        </h1>
        <div class="flex items-center gap-2">
          <span class="font-mono text-xs tabular-nums text-myth-text-lo">
            {items().length} items · {selectedCount()} selected
          </span>
          <button
            type="button"
            class="rounded-sm border border-myth-line bg-myth-bg-1 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
            onClick={() => refreshQuarantine()}
            disabled={busy()}
          >
            Refresh
          </button>
        </div>
      </header>

      <Show when={currentBatchProgress()}>
        <section class="rounded-md border border-myth-line bg-myth-bg-1 p-3">
          <ProgressBar
            done={currentBatchProgress()!.items_done}
            total={currentBatchProgress()!.items_total}
            label={`${currentBatchProgress()!.kind === "restore" ? "Restoring" : "Deleting"} ${currentBatchProgress()!.items_done}/${currentBatchProgress()!.items_total}`}
          />
        </section>
      </Show>

      <section class="flex flex-wrap items-center gap-2">
        <button
          type="button"
          class="rounded-sm border border-myth-line bg-myth-bg-1 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50"
          disabled={busy() || items().length === 0}
          onClick={onRestoreAll}
        >
          Restore all
        </button>
        <button
          type="button"
          class="rounded-sm border border-myth-line bg-myth-bg-1 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50"
          disabled={busy() || selectedCount() === 0}
          onClick={onRestoreSelected}
        >
          Restore selected
        </button>
        <button
          type="button"
          class="rounded-sm border border-myth-line bg-myth-bg-1 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50"
          disabled={busy() || selectedCount() === 0}
          onClick={onDeleteSelected}
        >
          Delete selected
        </button>
        <div class="ml-auto flex items-center gap-2">
          <input
            type="text"
            placeholder="Type DELETE to enable"
            class="rounded-sm border border-myth-line bg-myth-bg-0 px-2 py-1 font-mono text-xs text-myth-text-hi placeholder-myth-text-lo focus:border-myth-bad focus:outline-none"
            value={confirmText()}
            onInput={(e) => setConfirmText(e.currentTarget.value)}
          />
          <button
            type="button"
            class="rounded-sm border border-myth-bad bg-myth-bad/10 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-bad hover:bg-myth-bad/20 disabled:cursor-not-allowed disabled:opacity-50"
            disabled={
              busy() || items().length === 0 || confirmText() !== "DELETE"
            }
            onClick={onDeleteAll}
          >
            Delete all
          </button>
        </div>
      </section>

      <Show when={lastError()}>
        <div class="rounded-md border border-myth-bad/50 bg-myth-bad/10 p-3 font-mono text-xs text-myth-bad">
          {lastError()}
        </div>
      </Show>

      <Show when={lastReport()}>
        <div class="rounded-md border border-myth-good/30 bg-myth-good/5 p-3 font-mono text-xs text-myth-text-md">
          batch #{lastReport()!.batch_id} ({lastReport()!.kind}):{" "}
          {lastReport()!.items_done}/{lastReport()!.items_total} items,{" "}
          {lastReport()!.errors.length} errors
        </div>
      </Show>

      <Show
        when={items().length > 0}
        fallback={
          <div class="rounded-md border border-dashed border-myth-line bg-myth-bg-1 p-6 text-center text-sm text-myth-text-lo">
            Nothing in quarantine.
          </div>
        }
      >
        <section class="overflow-hidden rounded-md border border-myth-line bg-myth-bg-1">
          <table class="w-full">
            <thead class="border-b border-myth-line text-left text-xs uppercase tracking-wide text-myth-text-lo">
              <tr>
                <th class="px-4 py-2 font-medium" />
                <th class="px-4 py-2 font-medium">ID</th>
                <th class="px-4 py-2 font-medium">Original path</th>
                <th class="px-4 py-2 font-medium text-right">Bytes</th>
                <th class="px-4 py-2 font-medium">Quarantined</th>
                <th class="px-4 py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items().map((r) => (
                <tr class="border-b border-myth-line/50 last:border-b-0">
                  <td class="px-4 py-2">
                    <input
                      type="checkbox"
                      checked={selectedQuarantineIds().has(r.id)}
                      onChange={() => toggleSelected(r.id)}
                    />
                  </td>
                  <td class="px-4 py-2 font-mono text-xs tabular-nums text-myth-text-md">
                    {r.id}
                  </td>
                  <td class="max-w-xl px-4 py-2">
                    <PathDisplay path={r.original_path} />
                  </td>
                  <td class="px-4 py-2 text-right font-mono text-xs tabular-nums text-myth-text-md">
                    {r.size_bytes.toLocaleString("en-US")}
                  </td>
                  <td class="px-4 py-2 font-mono text-xs tabular-nums text-myth-text-md">
                    {formatTimestamp(r.quarantined_at_utc)}
                  </td>
                  <td class="px-4 py-2 text-right">
                    <button
                      type="button"
                      class="mr-1 rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-0.5 font-mono text-xs uppercase text-myth-text-md hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50"
                      disabled={busy()}
                      onClick={() => onRestoreSingle(r.id)}
                    >
                      Restore
                    </button>
                    <button
                      type="button"
                      class="rounded-sm border border-myth-bad/50 bg-myth-bad/10 px-2 py-0.5 font-mono text-xs uppercase text-myth-bad hover:bg-myth-bad/20 disabled:cursor-not-allowed disabled:opacity-50"
                      disabled={busy()}
                      onClick={() => onDeleteSingle(r.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </Show>
    </div>
  );
};

function formatTimestamp(unix: number): string {
  return new Date(unix * 1000).toISOString().replace("T", " ").slice(0, 19);
}

export default Quarantine;
