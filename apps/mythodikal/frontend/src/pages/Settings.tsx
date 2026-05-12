// Settings page (TASK-041 + TASK-132 + TASK-133 + TASK-157).
//
// Sub-tabs: General | Scanning | Updates | Privacy | About.
//
// What's editable today (config-backed):
//   * General → start_with_os (TASK-157), close_action
//   * Scanning → archives_enabled, follow_symlinks, skip_hidden
//   * Privacy → telemetry_enabled (off by default per FR-110)
//   * Updates → dual-pane Engine + Virus database channels (TASK-133)

import type { Component, JSX } from "solid-js";
import { For, Show, createResource, createSignal, onCleanup } from "solid-js";
import {
  autostartGet,
  autostartSet,
  engineInstallUpdate,
  feedUpdateNow,
  onDbUpdateProgress,
  onEngineUpdateProgress,
  settingsGet,
  settingsUpdate,
  updaterDbCheckNow,
  updaterDbSetAuto,
  updaterDbState,
  updaterEngineCheckNow,
  updaterEngineSetAuto,
  updaterEngineState,
  updaterStatus,
} from "@/ipc/invoke";
import type {
  AutostartState,
  DatabaseChannelStateView,
  DatabaseUpdateProgressEvent,
  EngineUpdateAvailableView,
  EngineUpdateProgressEvent,
  FeedUpdateResult,
  SettingsPatch,
  SettingsSnapshot,
  UpdateChannelStateView,
  UpdaterStatusView,
} from "@/ipc/types";

type Tab = "general" | "scanning" | "updates" | "privacy" | "about";

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

  // TASK-157 — autostart toggle reads OS state every render so the UI
  // matches reality even after the OS keychain / .desktop file was
  // edited out-of-band.
  const [autostart, { refetch: refetchAutostart }] =
    createResource<AutostartState>(autostartGet);
  const [autostartBusy, setAutostartBusy] = createSignal(false);
  const onAutostartToggle = async (v: boolean) => {
    setAutostartBusy(true);
    try {
      await autostartSet(v);
      await refetchAutostart();
    } catch (err) {
      setSaveError(String(err));
    } finally {
      setAutostartBusy(false);
    }
  };

  // TASK-133 — Updates dual-pane resources.
  const [engineState, { refetch: refetchEngine }] =
    createResource<UpdateChannelStateView>(updaterEngineState);
  const [dbState, { refetch: refetchDb }] =
    createResource<DatabaseChannelStateView>(updaterDbState);
  const [engineCheckResult, setEngineCheckResult] = createSignal<
    EngineUpdateAvailableView | null
  >(null);
  const [engineBusy, setEngineBusy] = createSignal(false);
  const [engineProgress, setEngineProgress] =
    createSignal<EngineUpdateProgressEvent | null>(null);
  const [dbBusy, setDbBusy] = createSignal(false);
  const [dbProgress, setDbProgress] =
    createSignal<DatabaseUpdateProgressEvent | null>(null);

  // Wire the engine/db progress events for as long as the page is
  // mounted. onCleanup detaches on unmount.
  const enginePromise = onEngineUpdateProgress((p) => setEngineProgress(p));
  const dbPromise = onDbUpdateProgress((p) => setDbProgress(p));
  onCleanup(() => {
    void enginePromise.then((fn) => fn());
    void dbPromise.then((fn) => fn());
  });

  const apply = async (patch: SettingsPatch) => {
    setSaveError(null);
    try {
      await settingsUpdate(patch);
      await refetch();
    } catch (err) {
      setSaveError(String(err));
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

  const onEngineCheck = async () => {
    setEngineBusy(true);
    try {
      const r = await updaterEngineCheckNow();
      setEngineCheckResult(r);
      await refetchEngine();
    } catch (err) {
      setSaveError(String(err));
    } finally {
      setEngineBusy(false);
    }
  };

  const onEngineInstall = async () => {
    setEngineBusy(true);
    try {
      await engineInstallUpdate();
      await refetchEngine();
    } catch (err) {
      setSaveError(String(err));
    } finally {
      setEngineBusy(false);
    }
  };

  const onDbCheck = async () => {
    setDbBusy(true);
    try {
      await updaterDbCheckNow();
      await refetchDb();
    } catch (err) {
      setSaveError(String(err));
    } finally {
      setDbBusy(false);
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
        {(["general", "scanning", "updates", "privacy", "about"] as Tab[]).map(
          (t) => (
            <button
              type="button"
              class={`-mb-px border-b-2 px-3 py-1 font-mono text-xs uppercase tracking-wide ${tab() === t ? "border-myth-accent text-myth-text-hi" : "border-transparent text-myth-text-lo hover:text-myth-text-md"}`}
              onClick={() => setTab(t)}
            >
              {t}
            </button>
          ),
        )}
      </nav>

      <Show when={snap()}>
        <Show when={tab() === "general"}>
          <section class="space-y-3 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
            <Toggle
              label="Start with operating system"
              value={autostart()?.enabled ?? false}
              disabled={autostartBusy()}
              note={
                autostart()?.mechanism
                  ? `OS mechanism: ${autostart()!.mechanism}`
                  : "TASK-157 — wired via tauri-plugin-autostart."
              }
              onChange={onAutostartToggle}
            />
            <Toggle
              label="Show tray icon"
              value={snap()!.general.show_tray_icon}
              note="TASK-158 — the tray icon is always shown when the platform supports it; this toggle is informational. On GNOME without the AppIndicator extension, the icon may be hidden by the desktop."
              onChange={(v) =>
                apply({ general: { show_tray_icon: v } })
              }
            />
            <Radio
              label="When I close the window"
              value={snap()!.general.close_action}
              options={[
                { value: "minimize_to_tray", label: "Minimize to tray" },
                { value: "quit", label: "Quit Mythodikal" },
              ]}
              onChange={(v) => apply({ general: { close_action: v } })}
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

        <Show when={tab() === "updates"}>
          <section class="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* TASK-133 — Engine channel pane */}
            <ChannelPane
              title="Engine"
              subtitle="The Mythodikal app binary. Signed with ed25519; published to GitHub Releases."
              state={engineState()}
              busy={engineBusy()}
              onCheck={onEngineCheck}
              onToggleAuto={async (v) => {
                await updaterEngineSetAuto(v);
                await refetchEngine();
              }}
              progress={engineProgress()}
              extra={
                <Show when={engineCheckResult()}>
                  <div class="rounded border border-myth-warn/50 bg-myth-warn/10 p-3 font-mono text-xs text-myth-text-md">
                    <div class="text-myth-warn">
                      Update available: v{engineCheckResult()!.latest_version}
                    </div>
                    <div class="mt-1 text-myth-text-lo">
                      Current: v{engineCheckResult()!.current_version} · Published{" "}
                      {fmtUtc(engineCheckResult()!.published_at_utc)}
                    </div>
                    <Show when={engineCheckResult()!.release_notes}>
                      <pre class="mt-2 max-h-32 overflow-auto whitespace-pre-wrap text-xs text-myth-text-md">
                        {engineCheckResult()!.release_notes}
                      </pre>
                    </Show>
                    <div class="mt-2">
                      <button
                        type="button"
                        class="rounded-sm border border-myth-accent bg-myth-accent px-3 py-1 font-mono text-xs uppercase text-white hover:bg-myth-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
                        disabled={engineBusy()}
                        onClick={onEngineInstall}
                      >
                        Download &amp; install
                      </button>
                    </div>
                  </div>
                </Show>
              }
            />

            {/* TASK-133 — Database channel pane */}
            <ChannelPane
              title="Virus database"
              subtitle="abuse.ch hashes, NSRL allowlist, ... — separate from the engine. No rate limit; update as often as you like (FR-156)."
              state={dbState()?.state}
              busy={dbBusy()}
              onCheck={onDbCheck}
              onToggleAuto={async (v) => {
                await updaterDbSetAuto(v);
                await refetchDb();
              }}
              progress={
                dbProgress()
                  ? {
                      phase: `${dbProgress()!.feed_id}:${dbProgress()!.phase}`,
                      bytes_done: dbProgress()!.bytes_done,
                      bytes_total: dbProgress()!.bytes_total,
                      message: dbProgress()!.message,
                    }
                  : null
              }
              extra={
                <Show when={dbState() && dbState()!.feeds.length > 0}>
                  <div class="rounded border border-myth-line/60 bg-myth-bg-0 p-3">
                    <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                      Per-feed status
                    </div>
                    <table class="mt-2 w-full font-mono text-xs tabular-nums">
                      <thead class="text-left text-myth-text-lo">
                        <tr>
                          <th class="pr-3 font-medium">feed</th>
                          <th class="pr-3 font-medium">entries</th>
                          <th class="pr-3 font-medium">last install</th>
                          <th class="font-medium">outcome</th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={dbState()!.feeds}>
                          {(f) => (
                            <tr>
                              <td class="pr-3 text-myth-text-hi">
                                {f.feed_id}
                              </td>
                              <td class="pr-3 text-myth-text-md">
                                {f.entry_count.toLocaleString("en-US")}
                              </td>
                              <td class="pr-3 text-myth-text-md">
                                {fmtUtc(f.last_install_at_utc)}
                              </td>
                              <td class="text-myth-text-md">
                                {f.last_outcome}
                              </td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </div>
                </Show>
              }
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
              <table class="mt-1 w-full max-w-md font-mono text-xs tabular-nums">
                <tbody>
                  <Row
                    label="abuse.ch hashes"
                    value={snap()!.about.definition_count.abusech_hashes.toLocaleString(
                      "en-US",
                    )}
                    sub={
                      snap()!.about.definition_count.abusech_last_updated_utc
                        ? `Last updated ${fmtUtc(snap()!.about.definition_count.abusech_last_updated_utc!)}`
                        : "Not yet downloaded"
                    }
                  />
                  <Row
                    label="NSRL hashes"
                    value={snap()!.about.definition_count.nsrl_hashes.toLocaleString(
                      "en-US",
                    )}
                    sub={
                      snap()!.about.definition_count.nsrl_last_updated_utc
                        ? `Last updated ${fmtUtc(snap()!.about.definition_count.nsrl_last_updated_utc!)}`
                        : "Not yet downloaded"
                    }
                  />
                  <Row
                    label="Total active"
                    value={snap()!.about.definition_count.total.toLocaleString(
                      "en-US",
                    )}
                  />
                </tbody>
              </table>
              <div class="mt-2">
                <button
                  type="button"
                  class="rounded-sm border border-myth-line bg-myth-bg-0 px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:border-myth-accent hover:text-myth-text-hi disabled:cursor-not-allowed disabled:opacity-50"
                  disabled={engineBusy()}
                  onClick={onEngineCheck}
                >
                  Check for app updates
                </button>
              </div>
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

const Row: Component<{
  label: string;
  value: string;
  sub?: string;
}> = (props) => (
  <tr>
    <td class="py-0.5 pr-4 align-top text-xs uppercase tracking-wide text-myth-text-lo">
      {props.label}
    </td>
    <td class="py-0.5 align-top font-mono text-xs text-myth-text-hi">
      {props.value}
      <Show when={props.sub}>
        <div class="text-xs text-myth-text-lo">{props.sub}</div>
      </Show>
    </td>
  </tr>
);

const ChannelPane: Component<{
  title: string;
  subtitle: string;
  state: UpdateChannelStateView | undefined;
  busy: boolean;
  onCheck: () => void;
  onToggleAuto: (v: boolean) => Promise<void> | void;
  progress: { phase: string; bytes_done: number; bytes_total: number; message: string } | null;
  // Code-review CR-I10: precise the prior `any` so callers don't pass
  // arbitrary values.
  extra?: JSX.Element;
}> = (props) => {
  const fmtUtc = (sec: number) => {
    if (!sec) return "—";
    return new Date(sec * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
  };
  return (
    <section class="space-y-3 rounded-md border border-myth-line bg-myth-bg-1 p-4 text-sm text-myth-text-md">
      <header class="flex items-baseline justify-between">
        <h2 class="font-display text-lg font-semibold text-myth-text-hi">
          {props.title}
        </h2>
        <span class="font-mono text-xs uppercase tracking-wide text-myth-text-lo">
          {props.state?.last_outcome ?? "never"}
        </span>
      </header>
      <p class="text-xs text-myth-text-lo">{props.subtitle}</p>

      <div class="space-y-1 font-mono text-xs">
        <div>
          <span class="text-myth-text-lo">channel:</span>{" "}
          {props.state?.channel ?? "—"}
        </div>
        <div>
          <span class="text-myth-text-lo">last checked:</span>{" "}
          {fmtUtc(props.state?.last_check_at_utc ?? 0)}
        </div>
        <div>
          <span class="text-myth-text-lo">last installed:</span>{" "}
          {fmtUtc(props.state?.last_install_at_utc ?? 0)}
        </div>
        <Show when={props.state?.last_error}>
          <div class="text-myth-bad">last error: {props.state!.last_error}</div>
        </Show>
      </div>

      <Toggle
        label="Auto-update enabled"
        value={props.state?.auto_update_enabled ?? false}
        onChange={(v) => void props.onToggleAuto(v)}
      />

      <Show when={props.progress}>
        <div class="rounded border border-myth-line/60 bg-myth-bg-0 p-2 font-mono text-xs text-myth-text-md">
          <div>
            <span class="text-myth-text-lo">phase:</span>{" "}
            {props.progress!.phase}
          </div>
          <Show when={props.progress!.bytes_total > 0}>
            <div>
              <span class="text-myth-text-lo">progress:</span>{" "}
              {Math.round(
                (props.progress!.bytes_done / props.progress!.bytes_total) *
                  100,
              )}
              %
            </div>
          </Show>
          <Show when={props.progress!.message}>
            <div class="text-myth-text-lo">{props.progress!.message}</div>
          </Show>
        </div>
      </Show>

      <div>
        <button
          type="button"
          class="rounded-sm border border-myth-accent bg-myth-accent px-3 py-1 font-mono text-xs uppercase text-white hover:bg-myth-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
          disabled={props.busy}
          onClick={props.onCheck}
        >
          {props.busy ? "Checking…" : "Check now"}
        </button>
      </div>

      {props.extra}
    </section>
  );
};

export default Settings;
