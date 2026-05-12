// Settings page (TASK-035).
//
// Skeleton — Phase 3 reads the current snapshot and renders read-only
// fields with a "Phase 4 will make these editable" disclaimer. Real
// persistence + OS-state mirrors (FR-161 autostart, FR-162 tray) land
// in TASK-041 (Phase 4).

import type { Component } from "solid-js";
import { Show, createResource, createSignal } from "solid-js";
import { feedUpdateNow, settingsGet } from "@/ipc/invoke";
import type { FeedUpdateResult, SettingsSnapshot } from "@/ipc/types";

type Tab = "general" | "scanning" | "privacy" | "about";

const Settings: Component = () => {
  const [tab, setTab] = createSignal<Tab>("about");
  const [snap] = createResource<SettingsSnapshot>(settingsGet);
  const [authKey, setAuthKey] = createSignal("");
  const [nsrlPath, setNsrlPath] = createSignal("");
  const [feedReports, setFeedReports] = createSignal<FeedUpdateResult[]>([]);
  const [feedBusy, setFeedBusy] = createSignal(false);
  const [feedError, setFeedError] = createSignal<string | null>(null);

  const onUpdateFeeds = async () => {
    setFeedBusy(true);
    setFeedError(null);
    try {
      const r = await feedUpdateNow({
        abusech_auth_key: authKey().trim() || null,
        nsrl_local: nsrlPath().trim() || null,
      });
      setFeedReports(r);
    } catch (err) {
      setFeedError(String(err));
    } finally {
      setFeedBusy(false);
    }
  };

  return (
    <div class="flex h-full flex-col gap-4 p-6">
      <header class="flex items-center justify-between">
        <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
          Settings
        </h1>
        <span class="font-mono text-xs text-myth-text-lo">
          Phase 3 read-only · full editing arrives in Phase 4 (TASK-041)
        </span>
      </header>

      <nav class="flex gap-1 border-b border-myth-line">
        {(["general", "scanning", "privacy", "about"] as Tab[]).map((t) => (
          <button
            type="button"
            class={`-mb-px border-b-2 px-3 py-1 font-mono text-xs uppercase tracking-wide ${tab() === t ? "border-myth-accent text-myth-text-hi" : "border-transparent text-myth-text-lo hover:text-myth-text-md"}`}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </nav>

      <Show when={snap()}>
        <Show when={tab() === "general"}>
          <section class="space-y-2 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
            <Row
              label="Start with OS"
              value={String(snap()!.general.start_with_os)}
            />
            <Row
              label="Show tray icon"
              value={String(snap()!.general.show_tray_icon)}
            />
            <Row
              label="Close action"
              value={snap()!.general.close_action}
            />
          </section>
        </Show>

        <Show when={tab() === "scanning"}>
          <section class="space-y-2 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
            <Row
              label="Scan archives"
              value={String(snap()!.scanning.archives_enabled)}
            />
            <Row
              label="Follow symlinks"
              value={String(snap()!.scanning.follow_symlinks)}
            />
            <Row
              label="Skip hidden files"
              value={String(snap()!.scanning.skip_hidden)}
            />
          </section>
        </Show>

        <Show when={tab() === "privacy"}>
          <section class="space-y-2 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
            <Row
              label="Telemetry"
              value={
                snap()!.privacy.telemetry_enabled ? "ENABLED" : "OFF (default)"
              }
            />
            <p class="text-xs text-myth-text-lo">
              Per FR-110 telemetry is off by default. Mythodikal does not send
              any data from this machine without explicit opt-in. The default
              ships permanently disabled and there is no remote toggle.
            </p>
          </section>
        </Show>

        <Show when={tab() === "about"}>
          <section class="space-y-3 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
            <Row
              label="Engine version"
              value={snap()!.about.engine_version}
            />
            <div>
              <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                Definition count
              </div>
              <table class="mt-1 w-full max-w-sm font-mono text-xs tabular-nums">
                <tbody>
                  <Row
                    label="abuse.ch hashes"
                    value={snap()!.about.definition_count.abusech_hashes.toLocaleString(
                      "en-US",
                    )}
                  />
                  <Row
                    label="NSRL hashes"
                    value={snap()!.about.definition_count.nsrl_hashes.toLocaleString(
                      "en-US",
                    )}
                  />
                  <Row
                    label="Total active"
                    value={snap()!.about.definition_count.total.toLocaleString(
                      "en-US",
                    )}
                  />
                </tbody>
              </table>
            </div>
            <section class="space-y-2 rounded border border-myth-line/60 bg-myth-bg-0 p-3">
              <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                Update feeds now (FR-094 / FR-156)
              </div>
              <input
                type="text"
                placeholder="abuse.ch Auth-Key (free key at auth.abuse.ch)"
                class="w-full rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-1 font-mono text-xs"
                value={authKey()}
                onInput={(e) => setAuthKey(e.currentTarget.value)}
              />
              <input
                type="text"
                placeholder="Local NSRL hash list path (optional)"
                class="w-full rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-1 font-mono text-xs"
                value={nsrlPath()}
                onInput={(e) => setNsrlPath(e.currentTarget.value)}
              />
              <button
                type="button"
                class="rounded-sm border border-myth-accent bg-myth-accent px-3 py-1 font-mono text-xs uppercase text-white hover:bg-myth-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
                disabled={feedBusy()}
                onClick={onUpdateFeeds}
              >
                {feedBusy() ? "Updating…" : "Update feeds"}
              </button>
              <Show when={feedError()}>
                <div class="font-mono text-xs text-myth-bad">
                  {feedError()}
                </div>
              </Show>
              <Show when={feedReports().length > 0}>
                <ul class="font-mono text-xs text-myth-text-md">
                  {feedReports().map((r) => (
                    <li>
                      <span class="text-myth-text-lo">{r.feed_id}:</span>{" "}
                      {r.error
                        ? `failed: ${r.error}`
                        : `${r.merged_count.toLocaleString("en-US")} merged in ${r.elapsed_ms}ms`}
                    </li>
                  ))}
                </ul>
              </Show>
            </section>
          </section>
        </Show>
      </Show>
    </div>
  );
};

const Row: Component<{ label: string; value: string }> = (props) => (
  <tr>
    <td class="py-0.5 pr-4 text-xs uppercase tracking-wide text-myth-text-lo">
      {props.label}
    </td>
    <td class="py-0.5 font-mono text-xs text-myth-text-hi">{props.value}</td>
  </tr>
);

export default Settings;
