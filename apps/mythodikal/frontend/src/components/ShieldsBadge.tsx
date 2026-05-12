// ShieldsBadge (TASK-156).
//
// Always-visible status badge: green dot = ON, red dot = OFF/paused.
// Click drops a small menu with the FR-160.3 pause options. The badge
// is the sidebar's footer; the Settings → Real-time page hosts the
// full controls.

import { Show, createSignal, onCleanup, onMount } from "solid-js";
import { setShields, shieldsState, shieldsStatusText } from "@/stores/shields";

export const ShieldsBadge = () => {
  const [open, setOpen] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  // Wall-clock ticker so the "PAUSED · N min" label counts down without
  // a fresh event from the backend. Review feedback: prior version froze
  // at the minute the user clicked, even though the pause was expiring.
  const [now, setNow] = createSignal(Date.now());

  onMount(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    onCleanup(() => clearInterval(id));
  });

  const apply = async (enabled: boolean, pauseMinutes?: number) => {
    setBusy(true);
    setError(null);
    try {
      // The store's `shields:changed` subscription will mirror the new
      // state — we don't double-update from the resolved promise (review
      // feedback: setShields-then-broadcast was racing the broadcast).
      await setShields(enabled, pauseMinutes);
      setOpen(false);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const ok = () => shieldsState().enabled;
  // Recompute the text against `now()` so the signal re-reads it on tick.
  const label = () => shieldsStatusText(shieldsState(), now());

  return (
    <div class="relative">
      <button
        type="button"
        class="flex w-full items-center gap-2 text-left"
        onClick={() => setOpen((v) => !v)}
        disabled={busy()}
      >
        <span
          class={`h-2 w-2 rounded-full ${ok() ? "bg-myth-ok" : "bg-myth-bad"}`}
        />
        <span class="font-mono text-xs uppercase tracking-wide text-myth-text-md">
          Shields: {label()}
        </span>
      </button>
      <Show when={open()}>
        <div class="absolute bottom-full left-0 mb-2 w-44 rounded-md border border-myth-line bg-myth-bg-1 p-1 shadow-none">
          <Show when={ok()}>
            <MenuButton
              label="Pause 15 min"
              onClick={() => apply(false, 15)}
              busy={busy()}
            />
            <MenuButton
              label="Pause 1 hour"
              onClick={() => apply(false, 60)}
              busy={busy()}
            />
            <MenuButton
              label="Turn OFF"
              variant="bad"
              onClick={() => apply(false)}
              busy={busy()}
            />
          </Show>
          <Show when={!ok()}>
            <MenuButton
              label="Turn ON"
              variant="ok"
              onClick={() => apply(true)}
              busy={busy()}
            />
          </Show>
        </div>
      </Show>
      <Show when={error()}>
        <div class="mt-1 font-mono text-[10px] text-myth-bad">{error()}</div>
      </Show>
    </div>
  );
};

const MenuButton = (props: {
  label: string;
  variant?: "ok" | "bad";
  busy: boolean;
  onClick: () => void;
}) => {
  const variantClass = () => {
    if (props.variant === "ok") return "text-myth-ok";
    if (props.variant === "bad") return "text-myth-bad";
    return "text-myth-text-md";
  };
  return (
    <button
      type="button"
      class={`block w-full rounded-sm px-2 py-1 text-left font-mono text-xs uppercase tracking-wide ${variantClass()} hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50`}
      disabled={props.busy}
      onClick={props.onClick}
    >
      {props.label}
    </button>
  );
};
