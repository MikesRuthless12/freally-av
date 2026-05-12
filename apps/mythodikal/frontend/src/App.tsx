// App router (TASK-036).
//
// Wires the four Phase-3 routes underneath AppFrame. Event subscriptions
// (scan:*, quarantine:batch_progress) are attached here at app-mount
// time so they survive route changes — moving them inside a route's
// onMount let a scan started from /scan emit events into a void once
// the user navigated to /history (review fix).

import type { Component } from "solid-js";
import { Navigate, Route, Router } from "@solidjs/router";
import { AppFrame } from "@/components/AppFrame";
import Scan from "@/pages/Scan";
import History from "@/pages/History";
import Quarantine from "@/pages/Quarantine";
import Settings from "@/pages/Settings";
import { attachScanEvents } from "@/stores/scan";
import { attachQuarantineEvents } from "@/stores/quarantine";

const App: Component = () => {
  // Attach during the top-level render so the listeners' onCleanup
  // only fires on full app teardown.
  attachScanEvents();
  attachQuarantineEvents();
  return (
    <Router root={(props) => <AppFrame>{props.children}</AppFrame>}>
      <Route path="/" component={() => <Navigate href="/scan" />} />
      <Route path="/scan" component={Scan} />
      <Route path="/history" component={History} />
      <Route path="/quarantine" component={Quarantine} />
      <Route path="/settings" component={Settings} />
    </Router>
  );
};

export default App;
