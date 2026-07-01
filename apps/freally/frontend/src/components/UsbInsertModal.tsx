// USB-insert auto-trigger modal (TASK-241, Phase 8 Wave 2).
//
// Surfaced by the per-OS daemon when an unknown VID:PID:Serial USB
// device arrives. Three actions:
//   * Scan — kick off an on-demand scan scoped to the mountpoint.
//   * Skip — close the modal; remember "skip" for the device.
//   * Trust always — add to the allowlist (TASK-242) and skip in future.
//
// Per § 1.5.4 the device is never blocked from mounting. The modal is
// alert-only.

import { Show, type Component } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

export interface UsbInsertEvent {
  vid: string;
  pid: string;
  serial: string;
  label?: string | null;
  mountpoint?: string | null;
  port_path: string;
  first_seen_ms: number;
}

export interface UsbInsertModalProps {
  event: UsbInsertEvent | null;
  onClose: () => void;
}

export const UsbInsertModal: Component<UsbInsertModalProps> = (props) => {
  const trustAlways = async () => {
    if (!props.event) return;
    await invoke("usb_allowlist_add", {
      req: {
        vid: props.event.vid,
        pid: props.event.pid,
        serial: props.event.serial,
        label: props.event.label ?? "",
      },
    });
    props.onClose();
  };

  const scan = async () => {
    if (!props.event?.mountpoint) {
      props.onClose();
      return;
    }
    await invoke("scan_start", {
      request: {
        target_path: props.event.mountpoint,
        compute_sha256: true,
        follow_symlinks: false,
      },
    });
    props.onClose();
  };

  return (
    <Show when={props.event}>
      {(ev) => (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div class="w-[28rem] rounded-md border border-myth-line bg-myth-bg-1 p-5">
            <h2 class="font-display text-lg text-myth-text-hi">
              USB drive inserted
            </h2>
            <dl class="mt-3 grid grid-cols-[6rem_1fr] gap-1 font-mono text-xs">
              <dt class="text-myth-text-lo">VID:PID</dt>
              <dd class="text-myth-text-hi">
                {ev().vid}:{ev().pid}
              </dd>
              <dt class="text-myth-text-lo">Serial</dt>
              <dd class="text-myth-text-hi">{ev().serial || "(none)"}</dd>
              <Show when={ev().label}>
                <dt class="text-myth-text-lo">Label</dt>
                <dd class="text-myth-text-hi">{ev().label}</dd>
              </Show>
              <dt class="text-myth-text-lo">Mount</dt>
              <dd class="text-myth-text-hi">{ev().mountpoint ?? "(not mounted)"}</dd>
              <dt class="text-myth-text-lo">Port</dt>
              <dd class="text-myth-text-hi">{ev().port_path}</dd>
            </dl>
            <div class="mt-4 flex justify-end gap-2">
              <button
                type="button"
                class="rounded-sm border border-myth-line px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
                onClick={props.onClose}
              >
                Skip
              </button>
              <button
                type="button"
                class="rounded-sm border border-myth-line px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2"
                onClick={() => void trustAlways()}
              >
                Trust always
              </button>
              <button
                type="button"
                class="rounded-sm bg-myth-accent px-3 py-1 font-mono text-xs uppercase tracking-wide text-white hover:bg-myth-accent/80"
                onClick={() => void scan()}
              >
                Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </Show>
  );
};
