// Scan page (TASK-032; TASK-056 wave 2 — Windows per-volume target chooser).
//
// Single primary action (Start scan). When a scan is running the
// button row swaps to Pause / Cancel (both wired to the Phase 4 stubs
// in commands.rs — they return clear "Phase 4" errors today). After
// completion the user can start a new scan.

import type { Component } from "solid-js";
import { For, Show, createEffect, createSignal, onMount } from "solid-js";
import type {
  FindingAction,
  FindingView,
  VolumeView,
} from "@/ipc/types";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  enumerateVolumes,
  findingAction,
  quickScanPaths,
} from "@/ipc/invoke";
import {
  cancelScan,
  pauseScan,
  resumeScan,
  scanCounters,
  scanFindings,
  scanState,
  startScan,
} from "@/stores/scan";
import { EtaDisplay } from "@/components/EtaDisplay";
import { FindingRow } from "@/components/FindingRow";
import { PathDisplay, displayPath } from "@/components/PathDisplay";
import { ProgressBar } from "@/components/ProgressBar";
import { StatusPill } from "@/components/StatusPill";
import { ThroughputChart } from "@/components/ThroughputChart";

const PARTIAL_HASH_STORAGE_KEY = "freally.scan.operatorMode";
const INCLUDE_REGISTRY_KEY = "freally.scan.includeRegistry";
const INCLUDE_PROCESSES_KEY = "freally.scan.includeProcesses";
const INCLUDE_ARCHIVES_KEY = "freally.scan.includeArchives";
const RUN_HEURISTICS_KEY = "freally.scan.runHeuristics";

const readBoolKey = (key: string): boolean =>
  typeof window !== "undefined" && window.localStorage.getItem(key) === "1";
const writeBoolKey = (key: string, value: boolean): void => {
  if (typeof window !== "undefined") {
    window.localStorage.setItem(key, value ? "1" : "0");
  }
};

const Scan: Component = () => {
  const [target, setTarget] = createSignal("");
  // `computeSha` is kept as a constant `true` so the ScanRequest IPC
  // contract stays unchanged; the engine ignores the flag now and
  // computes SHA-256 only when at least one loaded detector requires
  // it (`DetectionPipeline::requires_sha256`).
  const computeSha = () => true;
  const [followSymlinks, setFollowSymlinks] = createSignal(false);
  // TASK-056 — Windows scan-target chooser. Empty array on non-Windows
  // hosts: the backend command returns [] and the per-volume row UI
  // collapses cleanly. `allVolumes` toggle drives TASK-053's
  // `MultiVolumeWalker.all_volumes(true)` fan-out.
  const [volumes, setVolumes] = createSignal<VolumeView[]>([]);
  const [allVolumes, setAllVolumes] = createSignal(false);
  // Phase 6 — registry + process phase toggles. Default OFF for
  // arbitrary folder / removable-drive scans because the user doesn't
  // necessarily want to inspect their persistence keys every time
  // they scan a USB stick. Auto-flips to ON when `allVolumes` is on
  // (full-system scan = include everything by default).
  // Persist these toggles in localStorage so a re-mount of the Scan
  // component (route navigation, first-run completion, etc.) doesn't
  // flip the user's choices back to false — fixes the user-visible
  // "checkboxes uncheck themselves when I start a scan" bug.
  const [includeRegistry, setIncludeRegistryRaw] = createSignal(
    readBoolKey(INCLUDE_REGISTRY_KEY),
  );
  const setIncludeRegistry = (v: boolean) => {
    writeBoolKey(INCLUDE_REGISTRY_KEY, v);
    setIncludeRegistryRaw(v);
  };
  const [includeProcesses, setIncludeProcessesRaw] = createSignal(
    readBoolKey(INCLUDE_PROCESSES_KEY),
  );
  const setIncludeProcesses = (v: boolean) => {
    writeBoolKey(INCLUDE_PROCESSES_KEY, v);
    setIncludeProcessesRaw(v);
  };
  // Phase 6 — scan inside ZIP archive entries. Off by default; opt-in
  // because per-archive open + per-entry hash adds real latency on
  // big backup folders.
  const [includeArchives, setIncludeArchivesRaw] = createSignal(
    readBoolKey(INCLUDE_ARCHIVES_KEY),
  );
  const setIncludeArchives = (v: boolean) => {
    writeBoolKey(INCLUDE_ARCHIVES_KEY, v);
    setIncludeArchivesRaw(v);
  };
  // Phase 6 — heuristic post-pass. After the main file scan finishes,
  // a separate heuristics pass walks the findings + signer metadata
  // collected during the scan and applies pattern matchers (unsigned
  // exe in %TEMP%, IFEO debugger pointing at non-system path, exec
  // file masquerading as a media extension, etc.) that don't have a
  // YARA-style detector yet. Stored locally so the toggle persists.
  const [runHeuristics, setRunHeuristicsRaw] = createSignal(
    readBoolKey(RUN_HEURISTICS_KEY),
  );
  const setRunHeuristics = (v: boolean) => {
    writeBoolKey(RUN_HEURISTICS_KEY, v);
    setRunHeuristicsRaw(v);
  };
  // When allVolumes flips on, auto-enable the system-wide phases.
  // The user can still uncheck them individually.
  const toggleAllVolumes = (v: boolean) => {
    setAllVolumes(v);
    if (v) {
      setIncludeRegistry(true);
      setIncludeProcesses(true);
    }
  };
  // TASK-134 — operator-mode toggle. Persists in localStorage so the
  // setting survives page reloads.
  const [operatorMode, setOperatorMode] = createSignal(
    typeof window !== "undefined"
      ? window.localStorage.getItem(PARTIAL_HASH_STORAGE_KEY) === "1"
      : false,
  );
  const setOperatorModePersistent = (v: boolean) => {
    setOperatorMode(v);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(PARTIAL_HASH_STORAGE_KEY, v ? "1" : "0");
    }
  };
  const [error, setError] = createSignal<string | null>(null);
  const [busyAction, setBusyAction] = createSignal<number | null>(null);

  // Phase 6 — auto-scroll to the active phase tile. When the engine
  // transitions registry → processes → files, scroll the active
  // section into view so the user doesn't have to chase progress
  // down the page on a Quick Scan / All Volumes run.
  let registryTileRef: HTMLElement | undefined;
  let processTileRef: HTMLElement | undefined;
  let fileTileRef: HTMLElement | undefined;
  let heuristicsTileRef: HTMLElement | undefined;
  let lastScrolledPhase = "";
  createEffect(() => {
    const phase = scanCounters().activePhase;
    if (phase === lastScrolledPhase) return;
    lastScrolledPhase = phase;
    // For the file phase, scroll the page all the way down so the
    // throughput chart is also visible (the chart lives below the
    // file tile). For the registry / process / heuristics phases,
    // align the tile to the top so the active phase is the first
    // thing the user sees.
    if (phase === "files") {
      // Defer one tick so any newly-mounted tile is in the layout
      // before we measure scrollHeight.
      setTimeout(() => {
        window.scrollTo({
          top: document.documentElement.scrollHeight,
          behavior: "smooth",
        });
      }, 50);
      return;
    }
    const target =
      phase === "registry"
        ? registryTileRef
        : phase === "processes"
          ? processTileRef
          : phase === "heuristics"
            ? heuristicsTileRef
            : fileTileRef;
    target?.scrollIntoView({ behavior: "smooth", block: "start" });
  });

  // Event subscriptions live in App.tsx so they survive route changes
  // (PRD § review fix: a scan kicked off here keeps emitting events even
  // after the user navigates to History — the singleton store must
  // catch them).

  onMount(async () => {
    // Best-effort: surface a per-volume chooser when the platform
    // supports it. Empty array on non-Windows.
    try {
      const list = await enumerateVolumes();
      setVolumes(list);
    } catch {
      // Non-fatal — the path-only chooser still works.
    }
  });

  const onBrowse = async () => {
    setError(null);
    try {
      const picked = await openDialog({
        directory: true,
        multiple: false,
        title: "Choose a folder to scan",
      });
      if (typeof picked === "string" && picked.length > 0) {
        setTarget(picked);
      }
    } catch (err) {
      setError(String(err));
    }
  };

  const onBrowseFile = async () => {
    setError(null);
    try {
      const picked = await openDialog({
        directory: false,
        multiple: false,
        title: "Choose a file to scan",
      });
      if (typeof picked === "string" && picked.length > 0) {
        setTarget(picked);
      }
    } catch (err) {
      setError(String(err));
    }
  };

  const onStart = async () => {
    setError(null);
    try {
      await startScan({
        target_path: target(),
        compute_sha256: computeSha(),
        follow_symlinks: followSymlinks(),
        emit_partial_hash: operatorMode(),
        all_volumes: allVolumes(),
        include_registry: includeRegistry(),
        include_processes: includeProcesses(),
        include_archives: includeArchives(),
        run_heuristics: runHeuristics(),
      });
    } catch (err) {
      setError(String(err));
    }
  };

  /// Registry-only / Process-only / Reg+Proc presets. No file walker
  /// at all — pass `files_disabled: true` so the engine skips the
  /// producer + worker pool.
  const startSystemSweep = async (
    registry: boolean,
    processes: boolean,
  ) => {
    setError(null);
    try {
      await startScan({
        target_path: "",
        compute_sha256: false,
        follow_symlinks: false,
        emit_partial_hash: false,
        all_volumes: false,
        include_registry: registry,
        include_processes: processes,
        files_disabled: true,
      });
    } catch (err) {
      setError(String(err));
    }
  };

  /// Quick Scan — registry + processes + every malware-hotspot
  /// directory. Bypasses the target picker entirely.
  const onQuickScan = async () => {
    setError(null);
    try {
      const paths = await quickScanPaths();
      if (paths.length === 0) {
        setError("Quick Scan: no hotspot directories resolved on this host.");
        return;
      }
      await startScan({
        target_path: paths[0]!,
        extra_paths: paths.slice(1),
        compute_sha256: computeSha(),
        follow_symlinks: false,
        emit_partial_hash: operatorMode(),
        all_volumes: false,
        // Quick Scan defaults Registry + Processes on (those are the
        // "quick threat sweep" part of the preset). Archive recursion
        // and heuristics respect the user's persisted toggle — if
        // they unchecked "Scan inside ZIP archives", Quick Scan
        // doesn't override it.
        include_registry: true,
        include_processes: true,
        include_archives: includeArchives(),
        run_heuristics: runHeuristics(),
      });
    } catch (err) {
      setError(String(err));
    }
  };

  const onFindingAction = async (f: FindingView, action: FindingAction) => {
    setBusyAction(f.id);
    setError(null);
    try {
      await findingAction(f.id, action);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusyAction(null);
    }
  };

  const stateLabel = () => {
    const s = scanState();
    switch (s.kind) {
      case "idle":
        return "idle";
      case "running":
        return "running";
      case "paused":
        return "paused";
      case "cancelled":
        return "cancelled";
      case "completed":
        return "completed";
      case "failed":
        return "failed";
    }
  };

  const startDisabled = () =>
    (target().trim().length === 0 && !allVolumes()) ||
    scanState().kind === "running";

  const onPause = async () => {
    setError(null);
    const s = scanState();
    if (s.kind !== "running") return;
    try {
      await pauseScan(s.scanId);
    } catch (err) {
      setError(String(err));
    }
  };

  const onResume = async () => {
    setError(null);
    const s = scanState();
    if (s.kind !== "paused") return;
    try {
      await resumeScan(s.scanId);
    } catch (err) {
      setError(String(err));
    }
  };

  const onCancel = async () => {
    setError(null);
    const s = scanState();
    if (s.kind !== "running" && s.kind !== "paused") return;
    try {
      await cancelScan(s.scanId);
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div class="flex h-full flex-col gap-4 p-6">
      <header class="flex items-center justify-between">
        <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
          Scan
        </h1>
        <StatusPill status={stateLabel()} />
      </header>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <label class="block text-sm font-medium text-myth-text-hi">
          Target path
        </label>
        <div class="mt-1 flex items-center gap-2">
          {/* Read-only label for the picked folder. The user can't type
              an arbitrary path — they pick via Browse or a volume chip. */}
          <div
            class={`flex-1 min-w-0 rounded-sm border border-myth-line bg-myth-bg-0 px-3 py-2 font-mono text-sm ${
              target() ? "text-myth-text-hi" : "text-myth-text-lo"
            } ${allVolumes() ? "opacity-50" : ""} overflow-hidden text-ellipsis whitespace-nowrap`}
            title={target()}
          >
            {target() || "No folder selected"}
          </div>
          <button
            type="button"
            class="rounded-sm border border-myth-line bg-myth-bg-0 px-3 py-2 font-mono text-xs uppercase tracking-wide text-myth-text-hi hover:border-myth-accent disabled:cursor-not-allowed disabled:opacity-50"
            onClick={onBrowse}
            disabled={allVolumes()}
            title="Browse for a folder…"
          >
            Folder…
          </button>
          <button
            type="button"
            class="rounded-sm border border-myth-line bg-myth-bg-0 px-3 py-2 font-mono text-xs uppercase tracking-wide text-myth-text-hi hover:border-myth-accent disabled:cursor-not-allowed disabled:opacity-50"
            onClick={onBrowseFile}
            disabled={allVolumes()}
            title="Browse for a single file…"
          >
            File…
          </button>
        </div>

        <Show when={volumes().length > 0}>
          <div class="mt-3">
            <div class="mb-2 text-xs uppercase tracking-wide text-myth-text-lo">
              Volumes ({volumes().length})
            </div>
            <div class="flex flex-wrap gap-2">
              <For each={volumes()}>
                {(v) => (
                  <button
                    type="button"
                    class="flex items-center gap-2 rounded-sm border border-myth-line bg-myth-bg-0 px-2 py-1 font-mono text-xs text-myth-text-hi hover:border-myth-accent disabled:cursor-not-allowed disabled:opacity-50"
                    onClick={() => setTarget(v.mount_path)}
                    disabled={allVolumes()}
                    title={`${v.fs_name}${v.is_removable ? " · removable" : ""} · serial 0x${v.serial.toString(16).toUpperCase().padStart(8, "0")}`}
                  >
                    <span aria-hidden="true">{v.is_removable ? "🔌" : "💽"}</span>
                    <span>{v.mount_path}</span>
                    <span
                      class={`rounded-sm px-1 text-[10px] uppercase tracking-wide ${
                        v.is_ntfs
                          ? "bg-myth-accent/20 text-myth-accent"
                          : "bg-myth-line/40 text-myth-text-md"
                      }`}
                    >
                      {v.fs_name}
                    </span>
                  </button>
                )}
              </For>
            </div>
            <label class="mt-3 flex items-center gap-2 text-sm text-myth-text-md">
              <input
                type="checkbox"
                checked={allVolumes()}
                onChange={(e) => toggleAllVolumes(e.currentTarget.checked)}
              />
              <span>
                Scan all volumes (per-volume parallel fan-out)
              </span>
            </label>
          </div>
        </Show>

        <div class="mt-3 flex flex-wrap gap-6 text-sm text-myth-text-md">
          {/* SHA-256 toggle retired — the engine now auto-detects whether
              any registered detector requires SHA-256 (abuse.ch hash
              blacklist, NSRL allowlist, BYOVD loldrivers) and skips the
              ~5× slower hash entirely when no detector needs it. The
              hidden `computeSha` signal still flows through ScanRequest
              for backwards-compat with the IPC contract; the engine
              ignores it. */}
          <label class="flex items-center gap-2">
            <input
              type="checkbox"
              checked={followSymlinks()}
              onChange={(e) => setFollowSymlinks(e.currentTarget.checked)}
            />
            <span>Follow symlinks</span>
          </label>
          <label
            class="flex items-center gap-2"
            title="FR-136 / TASK-134 — live mid-flight BLAKE3 prefix at ≤ 10 Hz. Off by default; slight CPU cost during scan."
          >
            <input
              type="checkbox"
              checked={operatorMode()}
              onChange={(e) =>
                setOperatorModePersistent(e.currentTarget.checked)
              }
            />
            <span>Operator mode (live hash preview)</span>
          </label>
          <label
            class="flex items-center gap-2"
            title="Phase 6 (preview) — enumerate Windows registry persistence keys (Run, Services, IFEO, Winlogon, …). The current sweep counts entries and surfaces the keys touched; deep value-data heuristics (unsigned exe in temp, IFEO redirect, etc.) arrive in a follow-up wave. Auto-on for All Volumes scans."
          >
            <input
              type="checkbox"
              checked={includeRegistry()}
              onChange={(e) => setIncludeRegistry(e.currentTarget.checked)}
            />
            <span>Include registry sweep</span>
          </label>
          <label
            class="flex items-center gap-2"
            title="Phase 6 — enumerate every running process and hash its main exe before scanning files. Auto-on for All Volumes scans."
          >
            <input
              type="checkbox"
              checked={includeProcesses()}
              onChange={(e) => setIncludeProcesses(e.currentTarget.checked)}
            />
            <span>Include process sweep</span>
          </label>
          <label
            class="flex items-center gap-2"
            title="Phase 6 — recurse into ZIP archive entries. Each entry is hashed; the archive itself counts as one file in the visited count."
          >
            <input
              type="checkbox"
              checked={includeArchives()}
              onChange={(e) => setIncludeArchives(e.currentTarget.checked)}
            />
            <span>Scan inside ZIP archives</span>
          </label>
          <label
            class="flex items-center gap-2"
            title="Phase 6 (preview) — after the file/registry/process sweep finishes, run heuristic pattern matchers over the collected metadata (unsigned exe in TEMP/AppData, IFEO debugger redirect, extension/MIME mismatch, suspicious autoruns). Adds a short post-scan pass; results appear in the Findings list."
          >
            <input
              type="checkbox"
              checked={runHeuristics()}
              onChange={(e) => setRunHeuristics(e.currentTarget.checked)}
            />
            <span>Run heuristics after scan</span>
          </label>
        </div>

        <div class="mt-4 flex gap-2">
          <button
            type="button"
            class="rounded-sm border border-myth-accent bg-myth-accent px-4 py-1.5 font-mono text-sm font-medium uppercase tracking-wide text-white hover:bg-myth-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            disabled={startDisabled()}
            onClick={onStart}
          >
            Start scan
          </button>
          <Show when={scanState().kind !== "running" && scanState().kind !== "paused"}>
            <button
              type="button"
              class="rounded-sm border border-myth-accent bg-myth-bg-0 px-4 py-1.5 font-mono text-sm font-medium uppercase tracking-wide text-myth-accent hover:bg-myth-accent/10"
              onClick={onQuickScan}
              title="Quick Scan — registry + processes + malware-hotspot folders (TEMP, AppData, Downloads, Startup, ProgramData/Temp)."
            >
              Quick Scan
            </button>
            <button
              type="button"
              class="rounded-sm border border-myth-line bg-myth-bg-0 px-4 py-1.5 font-mono text-sm uppercase tracking-wide text-myth-text-hi hover:border-myth-accent"
              onClick={() => startSystemSweep(true, false)}
              title="Registry-only sweep. No file walker."
            >
              Reg only
            </button>
            <button
              type="button"
              class="rounded-sm border border-myth-line bg-myth-bg-0 px-4 py-1.5 font-mono text-sm uppercase tracking-wide text-myth-text-hi hover:border-myth-accent"
              onClick={() => startSystemSweep(false, true)}
              title="Process-only sweep. No file walker."
            >
              Proc only
            </button>
            <button
              type="button"
              class="rounded-sm border border-myth-line bg-myth-bg-0 px-4 py-1.5 font-mono text-sm uppercase tracking-wide text-myth-text-hi hover:border-myth-accent"
              onClick={() => startSystemSweep(true, true)}
              title="Registry + Process sweep, no file walker."
            >
              Reg + Proc
            </button>
          </Show>
          <Show
            when={
              scanState().kind === "running" || scanState().kind === "paused"
            }
          >
            <button
              type="button"
              class="rounded-sm border border-myth-line bg-myth-bg-0 px-4 py-1.5 font-mono text-sm uppercase tracking-wide text-myth-text-hi hover:border-myth-accent"
              onClick={
                scanState().kind === "running" ? onPause : onResume
              }
            >
              {scanState().kind === "paused" ? "Resume" : "Pause"}
            </button>
            <button
              type="button"
              class="rounded-sm border border-myth-bad bg-myth-bg-0 px-4 py-1.5 font-mono text-sm uppercase tracking-wide text-myth-bad hover:bg-myth-bad/10"
              onClick={onCancel}
              title="Cancel the scan. Mid-hash abort fires within ~1 ms via the shared cooperative-abort flag — no resume token is written; this scan cannot be resumed."
            >
              Cancel
            </button>
          </Show>
        </div>
      </section>

      <Show when={scanState().kind !== "idle"}>
        {/* Phase 6 — Registry phase tile. Shows up only when the
            registry sweep is part of the scan. */}
        <Show when={scanCounters().registryItemsExpected !== null || scanCounters().registryItemsScanned > 0}>
          <section
            ref={registryTileRef}
            class={`rounded-md border p-4 ${
              scanCounters().activePhase === "registry"
                ? "border-myth-accent bg-myth-bg-1"
                : "border-myth-line bg-myth-bg-1 opacity-80"
            }`}
          >
            <h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-myth-text-md">
              Registry sweep
              <span class="ml-2 font-mono text-[10px] normal-case tracking-normal text-myth-text-lo">
                (preview · counts only)
              </span>
              <Show when={scanCounters().registryPhaseComplete}>
                <span class="ml-2 text-myth-good">· done</span>
              </Show>
            </h2>
            <ProgressBar
              done={scanCounters().registryItemsScanned}
              total={scanCounters().registryItemsExpected}
            />
            <div class="mt-2 grid grid-cols-2 gap-4 text-sm text-myth-text-md">
              <Stat
                label="Items scanned"
                value={`${scanCounters().registryItemsScanned.toLocaleString("en-US")}${
                  scanCounters().registryItemsExpected !== null
                    ? ` / ${scanCounters().registryItemsExpected!.toLocaleString("en-US")}`
                    : ""
                }`}
              />
              <div>
                <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                  Current key
                </div>
                <Show
                  when={scanCounters().registryCurrentKey}
                  fallback={
                    <span class="font-mono text-xs text-myth-text-lo">—</span>
                  }
                >
                  <PathDisplay path={scanCounters().registryCurrentKey!} />
                </Show>
              </div>
            </div>
          </section>
        </Show>

        {/* Phase 6 — Process phase tile. */}
        <Show when={scanCounters().processesExpected !== null || scanCounters().processesScanned > 0}>
          <section
            ref={processTileRef}
            class={`rounded-md border p-4 ${
              scanCounters().activePhase === "processes"
                ? "border-myth-accent bg-myth-bg-1"
                : "border-myth-line bg-myth-bg-1 opacity-80"
            }`}
          >
            <h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-myth-text-md">
              Process sweep
              <Show when={scanCounters().processPhaseComplete}>
                <span class="ml-2 text-myth-good">· done</span>
              </Show>
            </h2>
            <ProgressBar
              done={scanCounters().processesScanned}
              total={scanCounters().processesExpected}
            />
            <div class="mt-2 grid grid-cols-2 gap-4 text-sm text-myth-text-md">
              <Stat
                label="Processes scanned"
                value={`${scanCounters().processesScanned.toLocaleString("en-US")}${
                  scanCounters().processesExpected !== null
                    ? ` / ${scanCounters().processesExpected!.toLocaleString("en-US")}`
                    : ""
                }`}
              />
              <div class="min-w-0">
                <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                  Current process
                </div>
                <Show
                  when={scanCounters().processCurrentName}
                  fallback={
                    <span class="block font-mono text-xs text-myth-text-lo">—</span>
                  }
                >
                  <div
                    class="block overflow-hidden text-ellipsis whitespace-nowrap font-mono text-xs text-myth-text-hi"
                    title={`${scanCounters().processCurrentName ?? ""}${scanCounters().processCurrentExe ? ` (${scanCounters().processCurrentExe})` : ""}`}
                  >
                    {scanCounters().processCurrentName}
                    <Show when={scanCounters().processCurrentExe}>
                      <span class="ml-2 text-myth-text-lo">
                        ({scanCounters().processCurrentExe})
                      </span>
                    </Show>
                  </div>
                </Show>
              </div>
            </div>
          </section>
        </Show>

        <section
          ref={fileTileRef}
          class={`rounded-md border p-4 ${
            scanCounters().activePhase === "files"
              ? "border-myth-accent bg-myth-bg-1"
              : "border-myth-line bg-myth-bg-1 opacity-80"
          }`}
        >
          <h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-myth-text-md">
            File scan
          </h2>
          <ProgressBar
            done={scanCounters().filesVisited}
            total={(() => {
              // Prefer the locked total once enumeration completes.
              // Fall back to the running total while enumeration is
              // still in flight — that lets the percent + filled bar
              // show meaningful progress instead of staying empty for
              // the duration of a million-file enumeration.
              const c = scanCounters();
              if (c.filesTotalLocked !== null) return c.filesTotalLocked;
              return c.filesTotalRunning > 0 ? c.filesTotalRunning : null;
            })()}
            label={(() => {
              // In terminal states (cancelled/completed/failed) the
              // ProgressBar default of "X scanned · counting…" is
              // wrong — nothing is counting any more. Override with
              // the frozen counter so the user sees what got done.
              const kind = scanState().kind;
              if (kind === "running" || kind === "paused") return undefined;
              const c = scanCounters();
              const done = c.filesVisited.toLocaleString("en-US");
              return c.filesTotalLocked !== null
                ? `${done} / ${c.filesTotalLocked.toLocaleString("en-US")}`
                : `${done} scanned`;
            })()}
          />
          <div class="mt-3 grid grid-cols-4 gap-4 text-sm text-myth-text-md">
            <Stat
              label="Files visited"
              value={(() => {
                // TASK-137 / FR-135 — three-piece during enumeration,
                // canonical X/Y after the producer locks Y. In any
                // terminal state (cancelled / completed / failed /
                // idle) we drop the `counting…` suffix entirely
                // because nothing is counting any more — the value
                // freezes at whatever the engine reported last.
                const c = scanCounters();
                const visited = c.filesVisited.toLocaleString("en-US");
                if (c.enumerationLocked && c.filesTotalLocked !== null) {
                  return `${visited} / ${c.filesTotalLocked.toLocaleString("en-US")}`;
                }
                const kind = scanState().kind;
                const stillCounting = kind === "running" || kind === "paused";
                if (!stillCounting) {
                  return c.filesTotalRunning > c.filesVisited
                    ? `${visited} / ${c.filesTotalRunning.toLocaleString("en-US")}`
                    : visited;
                }
                const running = c.filesTotalRunning.toLocaleString("en-US");
                return `${visited} · ${running} · counting…`;
              })()}
            />
            <Stat
              label="Files hashed"
              value={scanCounters().filesHashed.toLocaleString("en-US")}
            />
            <Stat
              label="Findings"
              value={scanCounters().findingsCount.toLocaleString("en-US")}
            />
            <EtaDisplay />
          </div>
          {/* Phase 6 — archive entries scanned. The archive itself
              counts as 1 in `Files visited`; each entry inside is
              hashed and tallied here. Only show the tile when at
              least one entry has been processed (or the toggle is
              on); empty zero on a no-archives scan would clutter the
              UI. */}
          <Show when={scanCounters().archiveEntriesScanned > 0 || includeArchives()}>
            <div class="mt-3">
              <Stat
                label="Archive entries scanned"
                value={scanCounters().archiveEntriesScanned.toLocaleString("en-US")}
              />
              <div class="mt-2">
                <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                  Current archive entry
                </div>
                <Show
                  when={scanCounters().archiveCurrentPath}
                  fallback={
                    <span class="block font-mono text-xs text-myth-text-lo">—</span>
                  }
                >
                  {/* Top line: the actual file being hashed inside the
                      zip — this is what the user wants to see clearly,
                      so it gets the bright color and breaks wherever
                      it needs to (not truncated). */}
                  <div
                    class="break-all font-mono text-xs text-myth-text-hi"
                    title={scanCounters().archiveCurrentEntry ?? ""}
                  >
                    <Show
                      when={scanCounters().archiveCurrentEntry}
                      fallback={<span class="text-myth-text-lo">—</span>}
                    >
                      {scanCounters().archiveCurrentEntry}
                    </Show>
                  </div>
                  {/* Second line: dim, smaller — the archive's own
                      path with the `\\?\` prefix stripped (FR-UI: drive
                      letters, not extended-length paths). */}
                  <div
                    class="mt-0.5 break-all font-mono text-[10px] text-myth-text-lo"
                    title={displayPath(scanCounters().archiveCurrentPath!)}
                  >
                    inside {displayPath(scanCounters().archiveCurrentPath!)}
                  </div>
                </Show>
              </div>
            </div>
          </Show>
          <div class="mt-3">
            <div class="text-xs uppercase tracking-wide text-myth-text-lo">
              Current path
            </div>
            <Show
              when={scanCounters().currentPath}
              fallback={
                <span class="font-mono text-xs text-myth-text-lo">—</span>
              }
            >
              <PathDisplay path={scanCounters().currentPath!} />
            </Show>
          </div>
          <Show when={operatorMode() && scanCounters().partialHash}>
            <div class="mt-3">
              <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                Live BLAKE3 (operator mode)
              </div>
              <div class="break-all font-mono text-xs text-myth-text-hi">
                {scanCounters().partialHash}
              </div>
              <div class="mt-0.5 font-mono text-xs tabular-nums text-myth-text-lo">
                {scanCounters().partialBytesDone.toLocaleString("en-US")} bytes
                hashed
              </div>
            </div>
          </Show>
          <Show when={scanState().kind === "completed"}>
            <div class="mt-3 font-mono text-sm font-medium text-myth-text-hi tabular-nums">
              Completed in:{" "}
              {scanState().kind === "completed"
                ? formatDuration(
                    (scanState() as { durationMs: number }).durationMs,
                  )
                : ""}
            </div>
          </Show>
          <Show when={scanState().kind === "failed"}>
            <div class="mt-3 font-mono text-xs text-myth-bad">
              failed:{" "}
              {(scanState() as { message: string }).message}
            </div>
          </Show>
        </section>
        <ThroughputChart />

        {/* Phase 6 — heuristics post-pass tile. Shows up only after
            the heuristics phase has started, or completed with
            results. */}
        <Show when={scanCounters().heuristicsExpected !== null || scanCounters().heuristicsScanned > 0}>
          <section
            ref={heuristicsTileRef}
            class={`rounded-md border p-4 ${
              scanCounters().activePhase === "heuristics"
                ? "border-myth-accent bg-myth-bg-1"
                : "border-myth-line bg-myth-bg-1 opacity-80"
            }`}
          >
            <h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-myth-text-md">
              Heuristics
              <span class="ml-2 font-mono text-[10px] normal-case tracking-normal text-myth-text-lo">
                (preview · 1 rule)
              </span>
              <Show when={scanCounters().heuristicsPhaseComplete}>
                <span class="ml-2 text-myth-good">· done</span>
              </Show>
            </h2>
            <ProgressBar
              done={scanCounters().heuristicsScanned}
              total={scanCounters().heuristicsExpected}
            />
            <div class="mt-2 grid grid-cols-3 gap-4 text-sm text-myth-text-md">
              <Stat
                label="Items examined"
                value={`${scanCounters().heuristicsScanned.toLocaleString("en-US")}${
                  scanCounters().heuristicsExpected !== null
                    ? ` / ${scanCounters().heuristicsExpected!.toLocaleString("en-US")}`
                    : ""
                }`}
              />
              <Stat
                label="Flagged"
                value={scanCounters().heuristicsFlagged.toLocaleString("en-US")}
              />
              <div class="min-w-0">
                <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                  Current
                </div>
                <Show
                  when={scanCounters().heuristicsCurrentPath}
                  fallback={<span class="block font-mono text-xs text-myth-text-lo">—</span>}
                >
                  <div
                    class="block overflow-hidden text-ellipsis whitespace-nowrap font-mono text-xs text-myth-text-hi"
                    title={displayPath(scanCounters().heuristicsCurrentPath!)}
                  >
                    {displayPath(scanCounters().heuristicsCurrentPath!)}
                  </div>
                </Show>
              </div>
            </div>
          </section>
        </Show>
      </Show>

      <Show when={error()}>
        <div class="rounded-md border border-myth-bad/50 bg-myth-bad/10 p-3 font-mono text-xs text-myth-bad">
          {error()}
        </div>
      </Show>

      <Show when={scanFindings().length > 0}>
        <section class="overflow-hidden rounded-md border border-myth-line bg-myth-bg-1">
          <header class="flex items-center justify-between border-b border-myth-line px-4 py-2">
            <h2 class="text-sm font-semibold uppercase tracking-wide text-myth-text-md">
              Findings
            </h2>
            <span class="font-mono text-xs tabular-nums text-myth-text-lo">
              {scanCounters().findingsCount > scanFindings().length
                ? `showing latest ${scanFindings().length.toLocaleString("en-US")} of ${scanCounters().findingsCount.toLocaleString("en-US")} — view all in History`
                : `${scanFindings().length.toLocaleString("en-US")} surfaced`}
            </span>
          </header>
          {/* Cap at 70 vh so the list scrolls inside this panel
              instead of pushing the page taller — keeps the scan
              dashboard tiles + throughput chart in view above. */}
          <div class="max-h-[70vh] overflow-y-auto">
            {scanFindings().map((f) => (
              <FindingRow
                finding={f}
                busy={busyAction() === f.id}
                onAction={(a) => onFindingAction(f, a)}
              />
            ))}
          </div>
        </section>
      </Show>
    </div>
  );
};

const Stat: Component<{ label: string; value: string }> = (props) => (
  <div>
    <div class="text-xs uppercase tracking-wide text-myth-text-lo">
      {props.label}
    </div>
    <div class="font-mono text-lg tabular-nums text-myth-text-hi">
      {props.value}
    </div>
  </div>
);

/** Format a duration (in milliseconds) as `Xh Ym Zs` — e.g.
 *  9_133_000 ms → "2h 32m 13s", 80_500 ms → "1m 20s", 5_120 ms → "5s".
 *  Used for the "Completed in:" line on a finished scan. */
function formatDuration(ms: number): string {
  const totalS = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(totalS / 3600);
  const m = Math.floor((totalS % 3600) / 60);
  const s = totalS % 60;
  const pad = (n: number) => (n < 10 ? `0${n}` : `${n}`);
  if (h > 0) return `${h}h ${pad(m)}m ${pad(s)}s`;
  if (m > 0) return `${m}m ${pad(s)}s`;
  return `${s}s`;
}

export default Scan;
