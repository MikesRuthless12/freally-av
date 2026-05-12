// FindingRow (TASK-031).
//
// One row in the findings list shown on the Scan dashboard + History
// detail. Severity-coloured pill + path + rule + action menu (the
// menu is wired but action handling is owned by the parent so a
// single row stays decoupled from the store).

import type { Component } from "solid-js";
import { Show } from "solid-js";
import type { FindingAction, FindingView } from "@/ipc/types";
import { PathDisplay } from "./PathDisplay";
import { StatusPill } from "./StatusPill";

interface Props {
  finding: FindingView;
  onAction?: (action: FindingAction) => void;
  /** Disable action buttons (e.g. while a previous action is in flight). */
  busy?: boolean;
}

export const FindingRow: Component<Props> = (props) => {
  return (
    <div class="flex items-start gap-4 border-b border-myth-line px-4 py-2 last:border-b-0">
      <StatusPill status={props.finding.severity} />
      <div class="flex-1 min-w-0">
        <PathDisplay path={props.finding.path} />
        <div class="mt-0.5 font-mono text-xs text-myth-text-lo">
          {props.finding.rule_source}: {props.finding.rule_id}
        </div>
      </div>
      <StatusPill status={props.finding.action_taken} />
      <Show when={props.onAction}>
        <ActionMenu
          state={props.finding.action_taken}
          busy={props.busy}
          onAction={(a) => props.onAction?.(a)}
        />
      </Show>
    </div>
  );
};

const ActionMenu: Component<{
  state: string;
  busy?: boolean;
  onAction: (action: FindingAction) => void;
}> = (props) => {
  const allowed = (): FindingAction[] => {
    switch (props.state) {
      case "none":
        return ["quarantine", "delete", "ignore"];
      case "quarantined":
        return ["restore", "delete", "ignore"];
      default:
        return [];
    }
  };
  return (
    <div class="flex gap-1">
      {allowed().map((action) => (
        <button
          type="button"
          class="rounded-sm border border-myth-line bg-myth-bg-1 px-2 py-0.5 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2 disabled:cursor-not-allowed disabled:opacity-50"
          disabled={props.busy}
          onClick={() => props.onAction(action)}
        >
          {action}
        </button>
      ))}
    </div>
  );
};
