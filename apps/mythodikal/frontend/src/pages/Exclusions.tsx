// Exclusions page (TASK-042).
//
// Settings → Exclusions sub-tab. Lists active and expired rules; add
// new path / glob / hash exclusions with optional expiry. Per FR-060
// kinds: path, glob, hash_blake3, hash_sha256. Per FR-134 scope:
// scan_only | realtime_only | both, plus expiry.

import type { Component } from "solid-js";
import { For, Show, createResource, createSignal } from "solid-js";
import { exclusionAdd, exclusionList, exclusionRemove } from "@/ipc/invoke";
import type {
  ExclusionKind,
  ExclusionScope,
  ExclusionView,
} from "@/ipc/types";
import { StatusPill } from "@/components/StatusPill";

const Exclusions: Component = () => {
  const [list, { refetch }] = createResource<ExclusionView[]>(exclusionList);

  const [kind, setKind] = createSignal<ExclusionKind>("path");
  const [scope, setScope] = createSignal<ExclusionScope>("both");
  const [value, setValue] = createSignal("");
  const [reason, setReason] = createSignal("");
  const [expireHours, setExpireHours] = createSignal<number | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const onAdd = async () => {
    if (value().trim().length === 0) {
      setError("Value is required");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const expires = expireHours();
      await exclusionAdd({
        kind: kind(),
        value: value().trim(),
        scope: scope(),
        expires_at_utc:
          expires !== null && expires > 0
            ? Math.floor(Date.now() / 1000) + expires * 3600
            : null,
        reason: reason().trim() || null,
      });
      setValue("");
      setReason("");
      setExpireHours(null);
      void refetch();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const onRemove = async (id: number) => {
    setBusy(true);
    setError(null);
    try {
      await exclusionRemove(id);
      void refetch();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="flex h-full flex-col gap-4 p-6">
      <header class="flex items-center justify-between">
        <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
          Exclusions
        </h1>
        <button
          type="button"
          class="rounded-sm border border-myth-line bg-myth-bg-1 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
          onClick={() => refetch()}
          disabled={busy()}
        >
          Refresh
        </button>
      </header>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-myth-text-md">
          Add exclusion
        </h2>
        <div class="grid grid-cols-2 gap-3">
          <label class="text-sm text-myth-text-md">
            <div class="text-xs uppercase tracking-wide text-myth-text-lo">
              Kind
            </div>
            <select
              class="mt-1 w-full rounded-sm border border-myth-line bg-myth-bg-0 px-2 py-1 font-mono text-sm text-myth-text-hi focus:border-myth-accent focus:outline-none"
              value={kind()}
              onChange={(e) =>
                setKind(e.currentTarget.value as ExclusionKind)
              }
            >
              <option value="path">path</option>
              <option value="glob">glob</option>
              <option value="hash_blake3">hash_blake3</option>
              <option value="hash_sha256">hash_sha256</option>
            </select>
          </label>
          <label class="text-sm text-myth-text-md">
            <div class="text-xs uppercase tracking-wide text-myth-text-lo">
              Scope
            </div>
            <select
              class="mt-1 w-full rounded-sm border border-myth-line bg-myth-bg-0 px-2 py-1 font-mono text-sm text-myth-text-hi focus:border-myth-accent focus:outline-none"
              value={scope()}
              onChange={(e) =>
                setScope(e.currentTarget.value as ExclusionScope)
              }
            >
              <option value="both">both</option>
              <option value="scan_only">scan only</option>
              <option value="realtime_only">realtime only</option>
            </select>
          </label>
          <label class="col-span-2 text-sm text-myth-text-md">
            <div class="text-xs uppercase tracking-wide text-myth-text-lo">
              Value{" "}
              {kind().startsWith("hash") ? "(64-char hex)" : "(path or glob)"}
            </div>
            <input
              type="text"
              class="mt-1 w-full rounded-sm border border-myth-line bg-myth-bg-0 px-2 py-1 font-mono text-sm text-myth-text-hi focus:border-myth-accent focus:outline-none"
              placeholder={
                kind() === "path"
                  ? "/home/me/safe"
                  : kind() === "glob"
                  ? "*node_modules*"
                  : "64-char hex"
              }
              value={value()}
              onInput={(e) => setValue(e.currentTarget.value)}
            />
          </label>
          <label class="text-sm text-myth-text-md">
            <div class="text-xs uppercase tracking-wide text-myth-text-lo">
              Reason (optional)
            </div>
            <input
              type="text"
              class="mt-1 w-full rounded-sm border border-myth-line bg-myth-bg-0 px-2 py-1 font-mono text-sm text-myth-text-hi focus:border-myth-accent focus:outline-none"
              placeholder="Trusted dev folder"
              value={reason()}
              onInput={(e) => setReason(e.currentTarget.value)}
            />
          </label>
          <label class="text-sm text-myth-text-md">
            <div class="text-xs uppercase tracking-wide text-myth-text-lo">
              Expires in hours (FR-134, blank = permanent)
            </div>
            <input
              type="number"
              min="0"
              class="mt-1 w-full rounded-sm border border-myth-line bg-myth-bg-0 px-2 py-1 font-mono text-sm text-myth-text-hi focus:border-myth-accent focus:outline-none"
              placeholder="(permanent)"
              value={expireHours() ?? ""}
              onInput={(e) => {
                const v = e.currentTarget.valueAsNumber;
                setExpireHours(Number.isFinite(v) && v > 0 ? v : null);
              }}
            />
          </label>
        </div>
        <Show when={error()}>
          <div class="mt-2 font-mono text-xs text-myth-bad">{error()}</div>
        </Show>
        <div class="mt-3">
          <button
            type="button"
            class="rounded-sm border border-myth-accent bg-myth-accent px-3 py-1 font-mono text-xs uppercase text-white hover:bg-myth-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            disabled={busy()}
            onClick={onAdd}
          >
            Add
          </button>
        </div>
      </section>

      <Show
        when={(list() ?? []).length > 0}
        fallback={
          <div class="rounded-md border border-dashed border-myth-line bg-myth-bg-1 p-6 text-center text-sm text-myth-text-lo">
            No exclusions yet.
          </div>
        }
      >
        <section class="overflow-hidden rounded-md border border-myth-line bg-myth-bg-1">
          <table class="w-full">
            <thead class="border-b border-myth-line text-left text-xs uppercase tracking-wide text-myth-text-lo">
              <tr>
                <th class="px-4 py-2 font-medium">Kind</th>
                <th class="px-4 py-2 font-medium">Value</th>
                <th class="px-4 py-2 font-medium">Scope</th>
                <th class="px-4 py-2 font-medium">Expires</th>
                <th class="px-4 py-2 font-medium">Reason</th>
                <th class="px-4 py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <For each={list() ?? []}>
                {(e) => (
                  <tr class="border-b border-myth-line/50 last:border-b-0">
                    <td class="px-4 py-2">
                      <StatusPill status={String(e.kind)} />
                    </td>
                    <td class="max-w-md truncate px-4 py-2 font-mono text-xs text-myth-text-md">
                      {e.value}
                    </td>
                    <td class="px-4 py-2 font-mono text-xs text-myth-text-md">
                      {String(e.scope)}
                    </td>
                    <td class="px-4 py-2 font-mono text-xs tabular-nums text-myth-text-md">
                      {formatExpiry(e.expires_at_utc)}
                    </td>
                    <td class="max-w-xs truncate px-4 py-2 text-xs text-myth-text-md">
                      {e.reason ?? "—"}
                    </td>
                    <td class="px-4 py-2 text-right">
                      <button
                        type="button"
                        class="rounded-sm border border-myth-bad/50 bg-myth-bad/10 px-2 py-0.5 font-mono text-xs uppercase text-myth-bad hover:bg-myth-bad/20 disabled:cursor-not-allowed disabled:opacity-50"
                        disabled={busy()}
                        onClick={() => onRemove(e.id)}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </section>
      </Show>
    </div>
  );
};

function formatExpiry(expiresAt: number | null): string {
  if (expiresAt === null) return "permanent";
  const now = Math.floor(Date.now() / 1000);
  if (expiresAt <= now) return "expired";
  const remaining = expiresAt - now;
  if (remaining < 3600) return `${Math.ceil(remaining / 60)} min left`;
  if (remaining < 86400) return `${Math.floor(remaining / 3600)} h left`;
  return `${Math.floor(remaining / 86400)} d left`;
}

export default Exclusions;
