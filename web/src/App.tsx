import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/layout/AppShell";
import { BenchmarkPage } from "./pages/BenchmarkPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DynamicSimulationPage } from "./pages/DynamicSimulationPage";
import { MetricsPage } from "./pages/MetricsPage";
import { RunHistoryPage } from "./pages/RunHistoryPage";
import { StaticScanPage } from "./pages/StaticScanPage";

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/static-scan" element={<StaticScanPage />} />
        <Route path="/dynamic-simulation" element={<DynamicSimulationPage />} />
        <Route path="/benchmarks" element={<BenchmarkPage />} />
        <Route path="/metrics" element={<MetricsPage />} />
        <Route path="/run-history" element={<RunHistoryPage />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}

