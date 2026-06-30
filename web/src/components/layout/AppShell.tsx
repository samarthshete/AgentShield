import { useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

import { checkHealth } from "../../lib/api";
import { ThemeToggle } from "../ui/ThemeToggle";

type NavItem = {
  label: string;
  path: string;
};

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", path: "/dashboard" },
  { label: "Static Scan", path: "/static-scan" },
  { label: "Dynamic Simulation", path: "/dynamic-simulation" },
  { label: "Benchmarks", path: "/benchmarks" },
  { label: "Metrics", path: "/metrics" },
  { label: "Run History", path: "/run-history" },
  { label: "Settings", path: "/settings" },
];

function navItemClass(isActive: boolean): string {
  return [
    "block rounded-lg border px-3 py-2 text-sm transition-colors",
    isActive
      ? "border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)] font-medium"
      : "border-transparent text-[var(--muted)] hover:border-[var(--border)] hover:bg-[var(--surface-muted)] hover:text-[var(--fg)]",
  ].join(" ");
}

function connectionIndicatorClass(status: "checking" | "reachable" | "offline"): string {
  if (status === "reachable") {
    return "bg-[var(--sev-clean-fg)]";
  }
  if (status === "offline") {
    return "bg-[var(--faint)]";
  }
  return "bg-[var(--sev-low-fg)]";
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<"checking" | "reachable" | "offline">("checking");
  const location = useLocation();
  const activeLabel = useMemo(
    () => NAV_ITEMS.find((item) => item.path === location.pathname)?.label ?? "Console",
    [location.pathname]
  );

  useEffect(() => {
    let active = true;
    void checkHealth().then((status) => {
      if (active) {
        setConnectionStatus(status);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="min-h-screen text-[var(--fg)]">
      <header
        className="sticky top-0 z-30 border-b border-[var(--border)] backdrop-blur"
        style={{ backgroundColor: "color-mix(in srgb, var(--surface) 82%, transparent)" }}
      >
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-2">
            <button
              className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--border)] text-[var(--muted)] md:hidden"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
            >
              <span className="text-sm font-bold">=</span>
            </button>
            <div className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent)]">
              <span className="text-sm font-bold">AS</span>
            </div>
            <div>
              <p className="text-sm font-semibold">AgentShield Console</p>
              <p className="text-xs text-[var(--muted)]">{activeLabel}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border)] bg-[var(--surface-muted)] px-2.5 py-1 text-xs text-[var(--muted)]">
              <span className={`h-2 w-2 rounded-full ${connectionIndicatorClass(connectionStatus)}`} />
              <span className="hidden sm:inline">
                {connectionStatus === "reachable"
                  ? "API reachable"
                  : connectionStatus === "offline"
                    ? "API offline"
                    : "Checking API"}
              </span>
              <span className="sm:hidden">
                {connectionStatus === "reachable" ? "API" : connectionStatus === "offline" ? "Off" : "..."}
              </span>
            </span>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <div className="mx-auto flex max-w-7xl gap-3 px-4 py-3 sm:gap-4 sm:px-6 sm:py-4">
        <aside className="sticky top-[72px] hidden h-[calc(100vh-88px)] w-64 shrink-0 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3 md:block">
          <nav className="space-y-1.5">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) => navItemClass(isActive)}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>

        <main className="min-w-0 flex-1">
          <Outlet />
        </main>
      </div>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <button
            className="absolute inset-0 bg-black/40"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation overlay"
          />
          <aside className="absolute left-0 top-0 h-full w-[88%] max-w-xs border-r border-[var(--border)] bg-[var(--surface)] p-4 shadow-lg">
            <div className="mb-4 flex items-center justify-between">
              <p className="text-sm font-semibold">Navigation</p>
              <button
                className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--border)] text-[var(--muted)]"
                onClick={() => setMobileOpen(false)}
                aria-label="Close navigation"
              >
                <span className="text-sm font-bold">X</span>
              </button>
            </div>
            <nav className="space-y-1.5">
              {NAV_ITEMS.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) => navItemClass(isActive)}
                  onClick={() => setMobileOpen(false)}
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </aside>
        </div>
      )}
    </div>
  );
}
