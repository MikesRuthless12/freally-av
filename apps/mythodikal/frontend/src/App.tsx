// App router (TASK-036).
//
// Wires the four Phase-3 routes underneath AppFrame. Event subscriptions
// (scan:*, quarantine:batch_progress) are attached here at app-mount
// time so they survive route changes — moving them inside a route's
// onMount let a scan started from /scan emit events into a void once
// the user navigated to /history (review fix).

import { Show, type Component } from "solid-js";
import { Navigate, Route, Router } from "@solidjs/router";
import { AppFrame } from "@/components/AppFrame";
import Scan from "@/pages/Scan";
import History from "@/pages/History";
import Quarantine from "@/pages/Quarantine";
import Exclusions from "@/pages/Exclusions";
import Settings from "@/pages/Settings";
import FirstRun from "@/pages/FirstRun";
import { attachScanEvents } from "@/stores/scan";
import { attachQuarantineEvents } from "@/stores/quarantine";
import { attachShieldsEvents } from "@/stores/shields";
import { attachTrayEvents } from "@/stores/tray";
import { firstRunCompleted } from "@/stores/firstRun";

const App: Component = () => {
  // Attach during the top-level render so the listeners' onCleanup
  // only fires on full app teardown. Subscriptions run even during the
  // FirstRun flow so we don't miss any backend events fired during
  // welcome (engine doesn't fire any until the user starts a scan, but
  // the order of attachment keeps the code symmetric).
  attachScanEvents();
  attachQuarantineEvents();
  attachShieldsEvents();
  attachTrayEvents();
  return (
    <Show
      when={firstRunCompleted()}
      fallback={
        <Router>
          <Route path="*" component={FirstRun} />
        </Router>
      }
    >
      <Router root={(props) => <AppFrame>{props.children}</AppFrame>}>
        <Route path="/" component={() => <Navigate href="/scan" />} />
        <Route path="/scan" component={Scan} />
        <Route path="/history" component={History} />
        <Route path="/quarantine" component={Quarantine} />
        <Route path="/exclusions" component={Exclusions} />
        <Route path="/settings" component={Settings} />
      </Router>
    </Show>
  );
};

export default App;
