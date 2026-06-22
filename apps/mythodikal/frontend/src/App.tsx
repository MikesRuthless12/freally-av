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
// Phase 8 Wave 1 — TASK-075 Real-time UI.
import Realtime from "@/pages/Realtime";
// Phase 8 Wave 2 — TASK-242 / TASK-245 / TASK-249 / TASK-250 USB pages.
import UsbAllowlist from "@/pages/Settings/UsbAllowlist";
import UsbPolicy from "@/pages/Settings/UsbPolicy";
import UsbWrites from "@/pages/History/UsbWrites";
import UsbDevices from "@/pages/UsbDevices";
// Phase 9 Wave 2 — TASK-253 macOS exemptions page.
import MacExemptions from "@/pages/Settings/MacExemptions";
import { attachScanEvents } from "@/stores/scan";
import { attachQuarantineEvents } from "@/stores/quarantine";
import { attachShieldsEvents } from "@/stores/shields";
import { attachTrayEvents } from "@/stores/tray";
import { firstRunCompleted, reconcileFirstRunFlag } from "@/stores/firstRun";
import { LocalizationProvider } from "@/i18n";

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
  // Reconcile the first-run flag with the backend-persisted file —
  // covers the dev-mode WebView2 profile reset (where localStorage
  // doesn't survive across rebuilds) so users don't re-see the
  // welcome flow on every launch.
  void reconcileFirstRunFlag();
  return (
    <LocalizationProvider>
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
          <Route path="/history/usb-writes" component={UsbWrites} />
          <Route path="/quarantine" component={Quarantine} />
          <Route path="/exclusions" component={Exclusions} />
          <Route path="/realtime" component={Realtime} />
          <Route path="/usb-devices" component={UsbDevices} />
          <Route path="/settings" component={Settings} />
          <Route path="/settings/usb-allowlist" component={UsbAllowlist} />
          <Route path="/settings/usb-policy" component={UsbPolicy} />
          <Route path="/settings/mac-exemptions" component={MacExemptions} />
        </Router>
      </Show>
    </LocalizationProvider>
  );
};

export default App;
