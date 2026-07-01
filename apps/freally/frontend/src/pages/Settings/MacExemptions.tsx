// macOS per-app real-time exemption settings (TASK-253, Phase 9 Wave 2).
//
// Each row is `(bundle_id, team_id, optional path_prefix)`. Adding or
// removing prompts the system-supplied Touch-ID / system-password
// sheet via the Keychain `kSecAttrAccessControl` item — the daemon
// owns the SecItem call; this page is just the surface.
//
// Per docs/prd.md § 1.5.4: exemptions short-circuit the engine call
// AFTER the kernel event; they never relax kernel policy. macOS-only
// — on other platforms this route renders a single "macOS only"
// message and disables the form.

import { For, Show, createResource, createSignal, type Component } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface MacExemption {
  bundle_id: string;
  team_id: string;
  path_prefix: string | null;
}

async function fetchList(): Promise<MacExemption[]> {
  try {
    return await invoke<MacExemption[]>("mac_exemption_list");
  } catch {
    return [];
  }
}

const MacExemptions: Component = () => {
  const [items, { refetch }] = createResource(fetchList);
  const [bundleId, setBundleId] = createSignal("");
  const [teamId, setTeamId] = createSignal("");
  const [pathPrefix, setPathPrefix] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const add = async (e: SubmitEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await invoke("mac_exemption_add", {
        bundleId: bundleId().trim(),
        teamId: teamId().trim(),
        pathPrefix: pathPrefix().trim() || null,
      });
      setBundleId("");
      setTeamId("");
      setPathPrefix("");
      await refetch();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (row: MacExemption) => {
    setBusy(true);
    setError(null);
    try {
      await invoke("mac_exemption_remove", {
        bundleId: row.bundle_id,
        teamId: row.team_id,
      });
      await refetch();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="flex flex-col gap-6 p-6">
      <header>
        <h1 class="font-display text-2xl text-myth-text-hi">macOS exemptions</h1>
        <p class="font-mono text-xs uppercase tracking-wide text-myth-text-lo">
          TASK-253 · Phase 9 Wave 2 · Keychain + Touch-ID
        </p>
      </header>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4 font-mono text-xs text-myth-text-md">
        <p>
          Each exemption is keyed by <strong>bundle id + team id</strong>. Pure
          path-based exemption is rejected — a renamed bundle would otherwise
          masquerade as the exempted one. Adding or removing requires a
          Touch-ID / system-password confirmation.
        </p>
        <p class="mt-2 text-myth-text-lo">
          Stored as a <code class="text-myth-text-md">kSecAttrAccessControl</code>
          Keychain item with <code class="text-myth-text-md">BiometryCurrentSet | Or | DevicePasscode</code>.
        </p>
      </section>

      <form
        class="grid grid-cols-[1.4fr_1fr_1.4fr_auto] items-end gap-2 rounded-md border border-myth-line bg-myth-bg-1 p-3"
        onSubmit={add}
      >
        <label class="flex flex-col gap-1">
          <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
            Bundle ID
          </span>
          <input
            class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
            placeholder="com.example.app"
            value={bundleId()}
            onInput={(e) => setBundleId(e.currentTarget.value)}
            required
          />
        </label>
        <label class="flex flex-col gap-1">
          <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
            Team ID
          </span>
          <input
            class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
            placeholder="ABCDE12345"
            value={teamId()}
            onInput={(e) => setTeamId(e.currentTarget.value)}
            required
            pattern="[A-Z0-9]{10}"
          />
        </label>
        <label class="flex flex-col gap-1">
          <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
            Path prefix (optional)
          </span>
          <input
            class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
            placeholder="/Users/me/Projects/"
            value={pathPrefix()}
            onInput={(e) => setPathPrefix(e.currentTarget.value)}
          />
        </label>
        <button
          type="submit"
          class="rounded-sm border border-myth-line bg-myth-bg-2 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-hi hover:bg-myth-bg-3 disabled:opacity-50"
          disabled={busy()}
        >
          {busy() ? "..." : "Add"}
        </button>
      </form>

      <Show when={error()}>
        <p class="font-mono text-xs text-myth-bad">{error()}</p>
      </Show>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <Show
          when={items() && items()!.length > 0}
          fallback={
            <p class="font-mono text-xs text-myth-text-lo">
              No exemptions yet. Every signed app routes through the engine
              by default.
            </p>
          }
        >
          <table class="w-full font-mono text-xs">
            <thead>
              <tr class="border-b border-myth-line text-left text-myth-text-lo">
                <th class="py-2">Bundle ID</th>
                <th class="py-2">Team ID</th>
                <th class="py-2">Path prefix</th>
                <th class="py-2 text-right" />
              </tr>
            </thead>
            <tbody>
              <For each={items()!}>
                {(row) => (
                  <tr class="border-b border-myth-line/30">
                    <td class="py-2 text-myth-text-hi">{row.bundle_id}</td>
                    <td class="py-2 text-myth-text-md">{row.team_id}</td>
                    <td class="py-2 text-myth-text-md">
                      {row.path_prefix ?? <span class="text-myth-text-lo">(any)</span>}
                    </td>
                    <td class="py-2 text-right">
                      <button
                        type="button"
                        class="rounded-sm border border-myth-line px-2 py-1 uppercase tracking-wide text-myth-bad hover:bg-myth-bg-2 disabled:opacity-50"
                        disabled={busy()}
                        onClick={() => void remove(row)}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </section>
    </div>
  );
};

export default MacExemptions;
