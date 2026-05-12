// AppFrame (TASK-036).
//
// Outer layout: sidebar on the left, page slot on the right. Used by
// the router as the parent of every route.

import type { Component, JSX } from "solid-js";
import { Sidebar } from "./Sidebar";

export const AppFrame: Component<{ children?: JSX.Element }> = (props) => {
  return (
    <div class="flex h-full bg-myth-bg-0 text-myth-text-hi">
      <Sidebar />
      <main class="flex-1 overflow-y-auto">{props.children}</main>
    </div>
  );
};
