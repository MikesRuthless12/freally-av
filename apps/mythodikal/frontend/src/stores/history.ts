// History store (TASK-030).
//
// Wraps history_list / history_get so the History page can render a
// table + drill-in detail without each component re-implementing
// loading state.

import { createResource, createSignal } from "solid-js";
import { historyGet, historyList } from "@/ipc/invoke";
import type { ScanDetail, ScanId, ScanSummary } from "@/ipc/types";

const [refreshTick, setRefreshTick] = createSignal(0);
const [selectedId, setSelectedId] = createSignal<ScanId | null>(null);

const [list] = createResource<ScanSummary[], number>(
  refreshTick,
  async () => {
    return await historyList(100, 0);
  },
);

const [detail] = createResource<ScanDetail | null, ScanId | null>(
  selectedId,
  async (id) => {
    if (id === null) return null;
    return await historyGet(id);
  },
);

export const historyListResource = list;
export const historyDetailResource = detail;

export function refreshHistory(): void {
  setRefreshTick((n) => n + 1);
}

export function selectScan(id: ScanId | null): void {
  setSelectedId(id);
}

export const selectedScanId = selectedId;
