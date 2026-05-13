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

const [detail, { mutate: mutateDetail }] = createResource<
  ScanDetail | null,
  ScanId | null
>(selectedId, async (id) => {
  if (id === null) return null;
  return await historyGet(id);
});

export const historyListResource = list;
export const historyDetailResource = detail;

/** Optimistically update one finding's `action_taken` in the
 *  currently-loaded detail without re-fetching from SQLite. Used by
 *  the History page after a per-row action so the panel doesn't
 *  flicker / reset scroll position. */
export function updateDetailFindingAction(
  findingId: number,
  newState: string,
): void {
  mutateDetail((prev) => {
    if (prev === null || prev === undefined) return prev;
    const next = {
      ...prev,
      findings: prev.findings.map((f) =>
        f.id === findingId ? { ...f, action_taken: newState } : f,
      ),
    };
    return next;
  });
}

export function refreshHistory(): void {
  setRefreshTick((n) => n + 1);
}

export function selectScan(id: ScanId | null): void {
  setSelectedId(id);
  // Solid's `createResource` skips the fetcher when the source
  // signal returns a falsy value and *keeps* the previously fetched
  // data visible — which is why the History "Close" button looked
  // dead. Force-clear the cached detail on deselect so `<Show
  // when={historyDetailResource()}>` collapses.
  if (id === null) {
    mutateDetail(null);
  }
}

export const selectedScanId = selectedId;
