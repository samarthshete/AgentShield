import { useState } from "react";

import { PageContainer } from "../components/layout/PageContainer";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { checkAuth, checkHealth } from "../lib/api";
import { getApiBaseUrl, getApiToken, setApiBaseUrl, setApiToken } from "../lib/settings";

type ConnectionStatus = "idle" | "checking" | "reachable" | "unauthorized" | "offline";

function statusBadge(status: ConnectionStatus) {
  if (status === "checking") {
    return <Badge variant="info">checking</Badge>;
  }
  if (status === "reachable") {
    return <Badge variant="success">reachable</Badge>;
  }
  if (status === "unauthorized") {
    return <Badge variant="warning">unauthorized</Badge>;
  }
  if (status === "offline") {
    return <Badge variant="danger">offline</Badge>;
  }
  return <Badge variant="neutral">not checked</Badge>;
}

function statusLine(status: ConnectionStatus): string {
  if (status === "reachable") {
    return "● reachable";
  }
  if (status === "unauthorized") {
    return "○ 401";
  }
  if (status === "offline") {
    return "○ offline";
  }
  if (status === "checking") {
    return "○ checking";
  }
  return "○ not checked";
}

export function SettingsPage() {
  const [apiBaseUrl, setApiBaseUrlInput] = useState(() => getApiBaseUrl());
  const [apiToken, setApiTokenInput] = useState(() => getApiToken());
  const [status, setStatus] = useState<ConnectionStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const saveSettings = () => {
    setApiBaseUrl(apiBaseUrl);
    setApiToken(apiToken);
    setSaved(true);
  };

  const checkConnection = async () => {
    setSaved(false);
    setError(null);
    saveSettings();
    setStatus("checking");
    const healthStatus = await checkHealth();
    if (healthStatus === "offline") {
      setStatus("offline");
      setError("The API health endpoint is offline. Check the base URL and backend process.");
      return;
    }

    const authStatus = await checkAuth();
    setStatus(authStatus);
    if (authStatus === "unauthorized") {
      setError("The API is reachable, but the token was rejected with 401.");
    } else if (authStatus === "offline") {
      setError("The API became unreachable while checking authenticated access.");
    }
  };

  return (
    <PageContainer
      title="Settings"
      subtitle="Runtime connection settings for the secured AgentShield API."
      actions={statusBadge(status)}
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <Card title="API Connection">
          <div className="space-y-4">
            <label className="block">
              <span className="mb-1 block text-xs font-semibold text-[var(--fg)]">API base URL</span>
              <input
                className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)] outline-none focus:border-[var(--accent)]"
                value={apiBaseUrl}
                onChange={(event) => {
                  setSaved(false);
                  setApiBaseUrlInput(event.target.value);
                }}
                placeholder="http://127.0.0.1:8000"
              />
            </label>

            <label className="block">
              <span className="mb-1 block text-xs font-semibold text-[var(--fg)]">API token</span>
              <input
                className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)] outline-none focus:border-[var(--accent)]"
                value={apiToken}
                onChange={(event) => {
                  setSaved(false);
                  setApiTokenInput(event.target.value);
                }}
                placeholder="AGENTSHIELD_API_TOKEN"
                type="password"
              />
            </label>

            <div className="flex flex-wrap items-center gap-2">
              <button
                className="rounded-md border border-[var(--accent)] bg-teal-700 px-3 py-2 text-sm font-medium text-white hover:bg-teal-800"
                onClick={saveSettings}
                type="button"
              >
                Save
              </button>
              <button
                className="rounded-md border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm font-medium text-[var(--fg)] hover:bg-[var(--surface-muted)]"
                disabled={status === "checking"}
                onClick={() => void checkConnection()}
                type="button"
              >
                Test connection
              </button>
              {saved ? <span className="text-xs text-[var(--muted)]">Saved locally</span> : null}
            </div>

            {error ? (
              <ErrorState
                message={error}
                onRetry={() => void checkConnection()}
                retryLabel="Test again"
              />
            ) : null}
          </div>
        </Card>

        <Card title="Connection Status">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <span className="font-medium text-[var(--fg)]">{statusLine(status)}</span>
              {statusBadge(status)}
            </div>
            <div className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-3 text-xs text-[var(--muted)]">
              <p className="font-mono text-[var(--fg)]">{apiBaseUrl || "http://127.0.0.1:8000"}</p>
              <p className="mt-2">{apiToken ? "Token configured" : "No token configured"}</p>
            </div>
          </div>
        </Card>
      </div>
    </PageContainer>
  );
}
