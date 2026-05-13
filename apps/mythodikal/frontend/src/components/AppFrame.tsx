// AppFrame (TASK-036).
//
// Outer layout: sidebar on the left, page slot on the right. Used by
// the router as the parent of every route.

import type { Component, JSX } from "solid-js";
import { Sidebar } from "./Sidebar";

export const AppFrame: Component<{ children?: JSX.Element }> = (props) => {
  return (
    // `w-full overflow-hidden` keeps the page-level horizontal scroll
    // from kicking in when a child has a single long text node (e.g.
    // a deep registry key path or a long process exe path). Without
    // it, a wider-than-viewport child grows the flex container past
    // the window edge — which then sticks even after a maximize →
    // restore cycle because the WebView's layout reuses the old
    // content-width measurement.
    <div class="flex h-full w-full overflow-hidden bg-myth-bg-0 text-myth-text-hi">
      <Sidebar />
      {/* `min-w-0` overrides flex's default `min-width: auto` so a
          long inline string inside the page can be truncated by its
          own ancestor's `overflow-hidden` / `text-ellipsis` rules
          instead of pushing the column wide. */}
      <main class="flex-1 min-w-0 overflow-y-auto">{props.children}</main>
    </div>
  );
};
