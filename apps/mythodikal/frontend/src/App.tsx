// App router (TASK-036).
//
// Wires the four Phase-3 routes underneath AppFrame.

import type { Component } from "solid-js";
import { Navigate, Route, Router } from "@solidjs/router";
import { AppFrame } from "@/components/AppFrame";
import Scan from "@/pages/Scan";
import History from "@/pages/History";
import Quarantine from "@/pages/Quarantine";
import Settings from "@/pages/Settings";

const App: Component = () => {
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
