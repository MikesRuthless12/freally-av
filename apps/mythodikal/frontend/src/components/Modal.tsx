// Modal component (TASK-062 — macOS UI parity polish).
//
// Platform-aware overlay container:
//   - macOS: "sheet" — slides down from the top edge of the window,
//     anchored to the title-bar area, with the spring-cubic-bezier easing
//     Apple's HIG specifies for sheets.
//   - Windows / Linux: centered modal with a fade+scale animation.
//
// Platform detection is via `navigator` (no @tauri-apps/plugin-os
// dependency added — keeps the deps lean and works in both Tauri WebView
// and plain-web environments). The CSS variants live in
// `src/styles/index.css` as `.modal--sheet` / `.modal--center`.
//
// SF Symbols: intentionally NOT used. SF Symbols are macOS-native and
// not directly renderable in HTML/CSS without licensed SVG copies.
// We use a Unicode close glyph (✕) which renders the same across all
// platforms and fits the cross-platform Mythodikal posture.

import { Show, type Component, type JSX } from "solid-js";

const isMacOS = (): boolean => {
  if (typeof navigator === "undefined") return false;
  // `navigator.platform` is deprecated but still the most reliable
  // signal inside Tauri's WKWebView. `userAgent` is the fallback.
  const plat = (navigator as Navigator & { userAgentData?: { platform?: string } });
  const uaPlatform = plat.userAgentData?.platform;
  if (uaPlatform) return uaPlatform === "macOS";
  return /Mac|Darwin/i.test(navigator.platform || "") ||
         /Mac OS X/i.test(navigator.userAgent || "");
};

type ModalProps = {
  /** Whether the modal is currently shown. */
  open: boolean;
  /** Invoked when the backdrop or close button is clicked. Required. */
  onClose: () => void;
  /** Optional header title rendered above the body. */
  title?: string;
  /** Body content. */
  children?: JSX.Element;
  /** Optional override class on the inner panel. */
  panelClass?: string;
};

/**
 * Renders nothing when `open` is `false`; otherwise renders a fixed,
 * platform-styled overlay with backdrop click-to-dismiss + ESC support
 * (handled via the backdrop click; ESC handler can be added by the
 * consumer if needed — kept out of the component to avoid global
 * keyboard-event coupling).
 */
const Modal: Component<ModalProps> = (props) => {
  const variantClass = isMacOS() ? "modal--sheet" : "modal--center";

  return (
    <Show when={props.open}>
      <div
        class="modal-backdrop"
        onClick={() => props.onClose()}
        role="presentation"
      >
        <div
          class={`modal ${variantClass} ${props.panelClass ?? ""}`}
          onClick={(e) => e.stopPropagation()}
          role="dialog"
          aria-modal="true"
          aria-labelledby={props.title ? "modal-title" : undefined}
        >
          <Show when={props.title}>
            <header class="modal__header">
              <h2 id="modal-title" class="modal__title">
                {props.title}
              </h2>
              <button
                type="button"
                class="modal__close"
                onClick={() => props.onClose()}
                aria-label="Close"
              >
                {"✕"}
              </button>
            </header>
          </Show>
          <div class="modal__body">{props.children}</div>
        </div>
      </div>
    </Show>
  );
};

export default Modal;
