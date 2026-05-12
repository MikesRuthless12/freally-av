// Quarantine store (TASK-030).
//
// Drives the Quarantine page: list, multi-select, and bulk-op
// progress subscription. The store doesn't own the UI's confirm
// modals — those live next to the page so the type-DELETE gate is
// always rendered, not always-on in state.

import { createResource, createSignal, onCleanup } from "solid-js";
import type { UnlistenFn } from "@tauri-apps/api/event";
import {
  onQuarantineBatchProgress,
  quarantineList,
} from "@/ipc/invoke";
import type {
  BatchProgressEvent,
  QuarantineId,
  QuarantineItem,
} from "@/ipc/types";

const [refreshTick, setRefreshTick] = createSignal(0);
const [batchProgress, setBatchProgress] =
  createSignal<BatchProgressEvent | null>(null);
const [selectedIds, setSelectedIds] = createSignal<Set<QuarantineId>>(
  new Set<QuarantineId>(),
);

const [list, { refetch }] = createResource<QuarantineItem[], number>(
  refreshTick,
  async () => {
    return await quarantineList();
  },
);

export const quarantineListResource = list;

export function refreshQuarantine(): void {
  setRefreshTick((n) => n + 1);
  void refetch();
}

export const currentBatchProgress = batchProgress;

export function toggleSelected(id: QuarantineId): void {
  setSelectedIds((prev) => {
    const next = new Set<QuarantineId>(prev);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  });
}

export function clearSelection(): void {
  setSelectedIds(new Set<QuarantineId>());
}

export const selectedQuarantineIds = selectedIds;

export function attachQuarantineEvents(): void {
  const handle = onQuarantineBatchProgress((p) => {
    setBatchProgress(p);
    if (p.items_done === p.items_total) {
      // Batch finished — clear UI state on the next tick so the
      // final 100% bar is visible briefly.
      setTimeout(() => {
        setBatchProgress(null);
        refreshQuarantine();
      }, 600);
    }
  });
  onCleanup(() => {
    void handle.then((fn: UnlistenFn) => fn());
  });
}
