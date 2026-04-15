import { useCallback, useEffect, useMemo, useState } from "react";

import { PageContainer } from "../components/layout/PageContainer";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { fetchJson } from "../lib/api";

type ScanRunHistoryItem = {
  id: string;
  target_path: string;
  mode: string;
  started_at: string;
  completed_at: string | null;
  findings_count: number;
  high_or_critical_count: number;
  overall_risk_score: number;
};

type DynamicRunHistoryItem = {
  id: string;
  scenario_id: string;
  scenario_name: string;
  category: string;
  ran_at: string;
  violation_count: number;
  raw_violation_count: number;
  max_severity: string | null;
  passed_clean: boolean;
  judge_type: string;
  judge_model: string | null;
};

type ScanHistoryResponse = {
  runs: ScanRunHistoryItem[];
};

type DynamicHistoryResponse = {
  runs: DynamicRunHistoryItem[];
};

type StaticFinding = {
  id: string;
  category: string;
  severity: string;
  title: string;
  evidence: string | null;
  recommendation: string | null;
  rule_id: string | null;
};

type DynamicViolation = {
  id: string;
  dynamic_run_id: string;
  policy_id: string;
  category: string;
  severity: string;
  title: string;
  evidence: string;
  step_seq: number | null;
  recommendation: string;
  status: "confirmed" | "dismissed";
};

type RunDetailsResponse = {
  run_id: string;
  run_type: "static" | "dynamic";
  static: {
    run: ScanRunHistoryItem;
    findings: StaticFinding[];
  } | null;
  dynamic: {
    run: DynamicRunHistoryItem;
    violations: DynamicViolation[];
  } | null;
};

function formatDateLabel(iso: string | null): string {
  if (!iso) {
    return "-";
  }
  return new Date(iso).toLocaleString();
}

function severityVariant(severity: string): "danger" | "warning" | "info" | "neutral" {
  const normalized = severity.toUpperCase();
  if (normalized === "CRITICAL" || normalized === "HIGH") {
    return "danger";
  }
  if (normalized === "MEDIUM") {
    return "warning";
  }
  if (normalized === "LOW") {
    return "info";
  }
  return "neutral";
}

function violationStatusVariant(status: "confirmed" | "dismissed"): "success" | "warning" {
  return status === "confirmed" ? "success" : "warning";
}

export function RunHistoryPage() {
  const [scanRuns, setScanRuns] = useState<ScanRunHistoryItem[]>([]);
  const [dynamicRuns, setDynamicRuns] = useState<DynamicRunHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [detail, setDetail] = useState<RunDetailsResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const [scanHistory, dynamicHistory] = await Promise.all([
        fetchJson<ScanHistoryResponse>("/api/history/scans?limit=40"),
        fetchJson<DynamicHistoryResponse>("/api/history/dynamic?limit=40"),
      ]);
      setScanRuns(scanHistory.runs);
      setDynamicRuns(dynamicHistory.runs);
    } catch (err) {
      setHistoryError(err instanceof Error ? err.message : "Failed to load run history.");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const loadRunDetails = useCallback(async (runId: string) => {
    setSelectedRunId(runId);
    setDetailLoading(true);
    setDetailError(null);
    try {
      const runDetails = await fetchJson<RunDetailsResponse>(`/api/runs/${runId}`);
      setDetail(runDetails);
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : "Failed to load run details.");
      setDetail(null);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const dynamicCounts = useMemo(() => {
    if (!detail || detail.run_type !== "dynamic" || !detail.dynamic) {
      return null;
    }
    const confirmed = detail.dynamic.violations.filter((violation) => violation.status === "confirmed").length;
    const dismissed = detail.dynamic.violations.filter((violation) => violation.status === "dismissed").length;
    return {
      confirmed,
      dismissed,
    };
  }, [detail]);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  return (
    <PageContainer
      title="Run History"
      subtitle="Browse persisted static and dynamic runs, then select any run to inspect details."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <button
            className="rounded-md border border-[var(--border)] bg-[var(--surface)] px-2.5 py-1 text-xs font-medium text-[var(--fg)] hover:bg-[var(--surface-muted)]"
            onClick={() => void loadHistory()}
          >
            Refresh
          </button>
          <Badge variant="neutral">GET /api/history/*</Badge>
        </div>
      }
    >
      {historyLoading ? <LoadingState label="Loading run history..." /> : null}
      {historyError ? <ErrorState message={historyError} onRetry={() => void loadHistory()} /> : null}

      {!historyLoading && !historyError ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title={`Static Runs (${scanRuns.length})`}>
            {scanRuns.length === 0 ? (
              <EmptyState
                title="No static runs"
                description="Run static scans to populate static run history."
              />
            ) : (
              <div className="overflow-auto">
                <table className="min-w-[680px] border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[var(--border)] text-[var(--fg)]">
                      <th className="p-2 font-semibold">Timestamp</th>
                      <th className="p-2 font-semibold">Findings</th>
                      <th className="p-2 font-semibold">High/Critical</th>
                      <th className="p-2 font-semibold">Risk</th>
                      <th className="p-2 font-semibold">Status</th>
                      <th className="p-2 font-semibold">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanRuns.map((run) => (
                      <tr key={run.id} className="border-b border-[var(--border)]">
                        <td className="p-2">{formatDateLabel(run.started_at)}</td>
                        <td className="p-2">{run.findings_count}</td>
                        <td className="p-2">{run.high_or_critical_count}</td>
                        <td className="p-2">{run.overall_risk_score}</td>
                        <td className="p-2">
                          <Badge variant={run.findings_count === 0 ? "success" : "warning"}>
                            {run.findings_count === 0 ? "clean" : "findings"}
                          </Badge>
                        </td>
                        <td className="p-2">
                          <button
                            className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] px-2 py-1 text-xs hover:bg-white"
                            onClick={() => void loadRunDetails(run.id)}
                          >
                            {selectedRunId === run.id ? "Selected" : "Inspect"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card title={`Dynamic Runs (${dynamicRuns.length})`}>
            {dynamicRuns.length === 0 ? (
              <EmptyState
                title="No dynamic runs"
                description="Run dynamic simulations to populate dynamic run history."
              />
            ) : (
              <div className="overflow-auto">
                <table className="min-w-[760px] border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[var(--border)] text-[var(--fg)]">
                      <th className="p-2 font-semibold">Timestamp</th>
                      <th className="p-2 font-semibold">Scenario</th>
                      <th className="p-2 font-semibold">Raw/Confirmed</th>
                      <th className="p-2 font-semibold">Max Severity</th>
                      <th className="p-2 font-semibold">Judge</th>
                      <th className="p-2 font-semibold">Status</th>
                      <th className="p-2 font-semibold">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dynamicRuns.map((run) => (
                      <tr key={run.id} className="border-b border-[var(--border)]">
                        <td className="p-2">{formatDateLabel(run.ran_at)}</td>
                        <td className="p-2">{run.scenario_id}</td>
                        <td className="p-2">
                          {run.raw_violation_count}/{run.violation_count}
                        </td>
                        <td className="p-2">
                          <Badge variant={run.max_severity ? severityVariant(run.max_severity) : "neutral"}>
                            {run.max_severity ?? "-"}
                          </Badge>
                        </td>
                        <td className="p-2">
                          <div className="flex flex-col gap-1">
                            <code>{run.judge_type}</code>
                            {run.judge_model ? <span className="text-[11px]">{run.judge_model}</span> : null}
                          </div>
                        </td>
                        <td className="p-2">
                          <Badge variant={run.passed_clean ? "success" : "warning"}>
                            {run.passed_clean ? "clean" : "violations"}
                          </Badge>
                        </td>
                        <td className="p-2">
                          <button
                            className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] px-2 py-1 text-xs hover:bg-white"
                            onClick={() => void loadRunDetails(run.id)}
                          >
                            {selectedRunId === run.id ? "Selected" : "Inspect"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      ) : null}

      <Card title="Selected Run Details">
        {detailLoading ? <LoadingState label="Loading selected run details..." /> : null}
        {detailError ? (
          <ErrorState
            message={detailError}
            onRetry={selectedRunId ? () => void loadRunDetails(selectedRunId) : undefined}
          />
        ) : null}

        {!detailLoading && !detailError && !detail ? (
          <EmptyState
            title="No run selected"
            description="Choose a run from static or dynamic history to inspect its details."
          />
        ) : null}

        {!detailLoading && !detailError && detail?.run_type === "static" && detail.static ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="info">static</Badge>
              <Badge variant={detail.static.run.findings_count === 0 ? "success" : "warning"}>
                {detail.static.run.findings_count === 0 ? "clean" : "findings"}
              </Badge>
              <span className="text-xs text-[var(--muted)]">
                {formatDateLabel(detail.static.run.started_at)}
              </span>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">Findings</p>
                <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{detail.static.run.findings_count}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">High/Critical</p>
                <p className="mt-1 text-lg font-semibold text-[var(--fg)]">
                  {detail.static.run.high_or_critical_count}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">Risk Score</p>
                <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{detail.static.run.overall_risk_score}</p>
              </div>
            </div>

            {detail.static.findings.length === 0 ? (
              <EmptyState title="No findings" description="This static run produced no findings." />
            ) : (
              <div className="space-y-2">
                {detail.static.findings.map((finding) => (
                  <div key={finding.id} className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={severityVariant(finding.severity)}>{finding.severity}</Badge>
                      <Badge variant="info">{finding.category}</Badge>
                      {finding.rule_id ? <code className="text-xs">{finding.rule_id}</code> : null}
                    </div>
                    <p className="mt-1 text-sm font-medium text-[var(--fg)]">{finding.title}</p>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      <strong>Evidence:</strong> {finding.evidence ?? "-"}
                    </p>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      <strong>Recommendation:</strong> {finding.recommendation ?? "-"}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : null}

        {!detailLoading && !detailError && detail?.run_type === "dynamic" && detail.dynamic ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="warning">dynamic</Badge>
              <Badge variant={detail.dynamic.run.passed_clean ? "success" : "warning"}>
                {detail.dynamic.run.passed_clean ? "clean" : "violations"}
              </Badge>
              <Badge variant="neutral">judge: {detail.dynamic.run.judge_type}</Badge>
              {detail.dynamic.run.judge_model ? (
                <Badge variant="neutral">model: {detail.dynamic.run.judge_model}</Badge>
              ) : null}
              {detail.dynamic.run.max_severity ? (
                <Badge variant={severityVariant(detail.dynamic.run.max_severity)}>
                  {detail.dynamic.run.max_severity}
                </Badge>
              ) : null}
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">Raw</p>
                <p className="mt-1 text-lg font-semibold text-[var(--fg)]">
                  {detail.dynamic.run.raw_violation_count}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">Confirmed</p>
                <p className="mt-1 text-lg font-semibold text-emerald-700">{dynamicCounts?.confirmed ?? 0}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">Dismissed</p>
                <p className="mt-1 text-lg font-semibold text-amber-700">{dynamicCounts?.dismissed ?? 0}</p>
              </div>
            </div>

            {detail.dynamic.violations.length === 0 ? (
              <EmptyState
                title="No violations recorded"
                description="This dynamic run has no persisted policy violations."
              />
            ) : (
              <div className="space-y-2">
                {detail.dynamic.violations.map((violation) => (
                  <div key={violation.id} className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={violationStatusVariant(violation.status)}>{violation.status}</Badge>
                      <Badge variant={severityVariant(violation.severity)}>{violation.severity}</Badge>
                      <code className="text-xs">{violation.policy_id}</code>
                      {violation.step_seq !== null ? <Badge variant="neutral">step {violation.step_seq}</Badge> : null}
                    </div>
                    <p className="mt-1 text-sm font-medium text-[var(--fg)]">{violation.title}</p>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      <strong>Evidence:</strong> {violation.evidence}
                    </p>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      <strong>Recommendation:</strong> {violation.recommendation || "-"}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : null}
      </Card>
    </PageContainer>
  );
}
