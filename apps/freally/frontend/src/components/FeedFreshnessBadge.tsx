// TASK-192 — Feed-freshness badge.
//
// One row per loaded feed, showing the upstream feed's
// `last_updated_utc` with an age-coloured tint. Surfaced on the
// dashboard so the user can spot a stuck updater without diving
// into Settings.
//
//   age <  24h  → --myth-good   (green)
//   age 24-72h  → neutral / --myth-text-md
//   age >  72h  → --myth-warn   (amber)
//
// Click → routes the user to Settings → Feeds (where they can also
// force a refresh per the existing engine_check_updates command).
// The component itself does NOT call any IPC — it's a presentational
// badge fed via props.

import type { Component } from "solid-js";
import { Show } from "solid-js";

export interface FeedFreshness {
  name: string;
  /** ISO-8601 UTC string returned by the existing About-page IPC,
   * or null when the feed has never been updated locally. */
  last_updated_utc: string | null;
  /** Number of entries currently loaded. Surfaced as a tooltip. */
  loaded_count?: number;
}

interface Props {
  feed: FeedFreshness;
  /** Optional click handler — typically routes to Settings → Feeds. */
  onClick?: () => void;
}

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

export const FeedFreshnessBadge: Component<Props> = (props) => {
  const age = (): { ms: number; tone: "good" | "neutral" | "warn" } | null => {
    const raw = props.feed.last_updated_utc;
    if (!raw) {
      return null;
    }
    const parsed = Date.parse(raw);
    if (Number.isNaN(parsed)) {
      return null;
    }
    const ms = Date.now() - parsed;
    let tone: "good" | "neutral" | "warn";
    if (ms < DAY_MS) {
      tone = "good";
    } else if (ms < 3 * DAY_MS) {
      tone = "neutral";
    } else {
      tone = "warn";
    }
    return { ms, tone };
  };

  const label = (): string => {
    const a = age();
    if (!a) {
      return "never";
    }
    const days = Math.floor(a.ms / DAY_MS);
    const hours = Math.floor((a.ms % DAY_MS) / HOUR_MS);
    if (days > 0) {
      return `${days}d ago`;
    }
    if (hours > 0) {
      return `${hours}h ago`;
    }
    return "<1h ago";
  };

  const toneClass = (): string => {
    const a = age();
    if (!a) {
      return "text-myth-text-lo border-myth-line";
    }
    switch (a.tone) {
      case "good":
        return "text-myth-good border-myth-good/40";
      case "warn":
        return "text-myth-warn border-myth-warn/60";
      default:
        return "text-myth-text-md border-myth-line";
    }
  };

  const tooltip = (): string => {
    const a = age();
    const last = props.feed.last_updated_utc ?? "never updated";
    const cnt = props.feed.loaded_count;
    const cntStr = cnt !== undefined ? ` · ${cnt.toLocaleString()} entries` : "";
    return `${props.feed.name}: last updated ${last}${cntStr}${
      a ? ` (${Math.floor(a.ms / HOUR_MS)} h ago)` : ""
    }`;
  };

  return (
    <button
      type="button"
      class={`flex items-center gap-2 rounded-sm border bg-myth-bg-1 px-2 py-1 font-mono text-xs ${toneClass()} hover:bg-myth-bg-2`}
      title={tooltip()}
      onClick={() => props.onClick?.()}
    >
      <span class="uppercase tracking-wide">{props.feed.name}</span>
      <span class="text-myth-text-lo">·</span>
      <span>{label()}</span>
      <Show when={props.feed.loaded_count !== undefined}>
        <span class="text-myth-text-lo">·</span>
        <span class="text-myth-text-md">
          {props.feed.loaded_count!.toLocaleString()}
        </span>
      </Show>
    </button>
  );
};
