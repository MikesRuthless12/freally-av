// Settings page (TASK-041, Phase 4 wave 2).
//
// Read-and-write surface backed by the live engine config. Each sub-tab
// renders its own section; mutations call `settings_update` with a
// partial patch and re-fetch the snapshot to render the persisted
// state. Toggling a field optimistically updates the UI; if the patch
// fails we revert and surface the error.
//
// What is editable today (config-backed):
//   * General → close_action (minimize_to_tray | quit)
//   * Scanning → archives_enabled, follow_symlinks, skip_hidden
//   * Privacy → telemetry_enabled (off by default per FR-110)
//
// What is read-only stub today:
//   * General → start_with_os, show_tray_icon (OS-state owned by
//     TASK-157 / TASK-158 — Tauri autostart + tray plugins)
//
// "Update feeds now" lives under the About tab as before.

import type { Component } from "solid-js";
import { Show, createResource, createSignal } from "solid-js";
import { feedUpdateNow, settingsGet, settingsUpdate, updaterStatus } from "@/ipc/invoke";
import type {
  FeedUpdateResult,
  SettingsPatch,
  SettingsSnapshot,
  UpdaterStatusView,
} from "@/ipc/types";

type Tab = "general" | "scanning" | "privacy" | "about";

const Settings: Component = () => {
  const [tab, setTab] = createSignal<Tab>("general");
  const [snap, { refetch }] = createResource<SettingsSnapshot>(settingsGet);
  const [updater, { refetch: refetchUpdater }] =
    createResource<UpdaterStatusView | null>(updaterStatus);
  const [authKey, setAuthKey] = createSignal("");
  const [nsrlPath, setNsrlPath] = createSignal("");
  const [feedReports, setFeedReports] = createSignal<FeedUpdateResult[]>([]);
  const [feedBusy, setFeedBusy] = createSignal(false);
  const [feedError, setFeedError] = createSignal<string | null>(null);
  const [saveError, setSaveError] = createSignal<string | null>(null);

  const apply = async (patch: SettingsPatch) => {
    setSaveError(null);
    try {
      await settingsUpdate(patch);
      await refetch();
    } catch (err) {
      setSaveError(String(err));
      // Re-fetch anyway so the UI returns to truth-from-engine.
      await refetch();
    }
  };

  const onUpdateFeeds = async () => {
    setFeedBusy(true);
    setFeedError(null);
    try {
      const r = await feedUpdateNow({
        abusech_auth_key: authKey().trim() || null,
        nsrl_local: nsrlPath().trim() || null,
      });
      setFeedReports(r);
      await refetchUpdater();
    } catch (err) {
      setFeedError(String(err));
    } finally {
      setFeedBusy(false);
    }
  };

  const fmtUtc = (sec: number) => {
    if (!sec) return "—";
    return new Date(sec * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
  };

  return (
    <div class="flex h-full flex-col gap-4 p-6">
      <header class="flex items-center justify-between">
        <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
          Settings
        </h1>
        <Show when={saveError()}>
          <span class="font-mono text-xs text-myth-bad">
            save failed: {saveError()}
          </span>
        </Show>
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
          <section class="space-y-3 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
            <Toggle
              label="Start with operating system"
              value={snap()!.general.start_with_os}
              disabled
              note="TASK-157 — Tauri autostart plugin wires this in a later wave."
              onChange={() => {}}
            />
            <Toggle
              label="Show tray icon"
              value={snap()!.general.show_tray_icon}
              disabled
              note="TASK-158 — Tray plugin wires this in a later wave."
              onChange={() => {}}
            />
            <Radio
              label="When I close the window"
              value={snap()!.general.close_action}
              options={[
                { value: "minimize_to_tray", label: "Minimize to tray" },
                { value: "quit", label: "Quit Mythodikal" },
              ]}
              onChange={(v) =>
                apply({ general: { close_action: v } })
              }
            />
          </section>
        </Show>

        <Show when={tab() === "scanning"}>
          <section class="space-y-3 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
            <Toggle
              label="Scan archive files (.zip, .7z, .tar, …)"
              value={snap()!.scanning.archives_enabled}
              onChange={(v) =>
                apply({ scanning: { archives_enabled: v } })
              }
            />
            <Toggle
              label="Follow symbolic links"
              value={snap()!.scanning.follow_symlinks}
              note="Off by default. Enabling can cause walker loops."
              onChange={(v) =>
                apply({ scanning: { follow_symlinks: v } })
              }
            />
            <Toggle
              label="Skip hidden files and folders"
              value={snap()!.scanning.skip_hidden}
              note="Affects dotfiles on Linux/macOS and hidden-attribute files on Windows."
              onChange={(v) => apply({ scanning: { skip_hidden: v } })}
            />
          </section>
        </Show>

        <Show when={tab() === "privacy"}>
          <section class="space-y-3 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
            <Toggle
              label="Send anonymous telemetry"
              value={snap()!.privacy.telemetry_enabled}
              onChange={(v) =>
                apply({ privacy: { telemetry_enabled: v } })
              }
            />
            <p class="text-xs text-myth-text-lo">
              Per FR-110, telemetry ships <strong>off by default</strong>. If
              opted-in, the scope is anonymous version + scan-count counter
              only — never paths, hashes, or IP addresses. The opt-in remains
              local to this machine; there is no remote toggle.
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
            <Show when={updater()}>
              <section class="space-y-1 rounded border border-myth-line/60 bg-myth-bg-0 p-3">
                <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                  Auto-updater status (TASK-043)
                </div>
                <Row
                  label="Last run"
                  value={fmtUtc(updater()!.finished_at_utc)}
                />
                <Row label="Outcome" value={updater()!.outcome} />
                <Row
                  label="Next run"
                  value={fmtUtc(updater()!.next_run_at_utc)}
                />
                <Show when={updater()!.detail}>
                  <pre class="whitespace-pre-wrap font-mono text-xs text-myth-text-md">
                    {updater()!.detail}
                  </pre>
                </Show>
              </section>
            </Show>
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

const Toggle: Component<{
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  note?: string;
}> = (props) => (
  <label class="flex flex-col gap-1 text-sm">
    <span class="flex items-center justify-between gap-3">
      <span class="text-myth-text-hi">{props.label}</span>
      <input
        type="checkbox"
        checked={props.value}
        disabled={props.disabled}
        class="h-4 w-4"
        onChange={(e) => props.onChange(e.currentTarget.checked)}
      />
    </span>
    <Show when={props.note}>
      <span class="text-xs text-myth-text-lo">{props.note}</span>
    </Show>
  </label>
);

const Radio: Component<{
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
}> = (props) => (
  <fieldset class="flex flex-col gap-2 text-sm">
    <legend class="text-myth-text-hi">{props.label}</legend>
    <div class="flex gap-4 pl-1">
      {props.options.map((o) => (
        <label class="flex items-center gap-2">
          <input
            type="radio"
            name={props.label}
            value={o.value}
            checked={props.value === o.value}
            onChange={() => props.onChange(o.value)}
          />
          <span class="text-myth-text-md">{o.label}</span>
        </label>
      ))}
    </div>
  </fieldset>
);

const Row: Component<{ label: string; value: string }> = (props) => (
  <tr>
    <td class="py-0.5 pr-4 text-xs uppercase tracking-wide text-myth-text-lo">
      {props.label}
    </td>
    <td class="py-0.5 font-mono text-xs text-myth-text-hi">{props.value}</td>
  </tr>
);

export default Settings;
