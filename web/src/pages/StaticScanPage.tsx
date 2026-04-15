import { FormEvent, useMemo, useState } from "react";

import { PageContainer } from "../components/layout/PageContainer";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { postJson } from "../lib/api";

type OutputFormat = "json" | "markdown" | "both";
type FailOnSeverity = "info" | "low" | "medium" | "high" | "critical";

type Finding = {
  id: string;
  category: string;
  severity: string;
  title: string;
  evidence: string | null;
  recommendation: string | null;
  rule_id: string | null;
  affected_component: string | null;
};

type ScanResponse = {
  scan_run: {
    id: string;
    started_at: string;
    completed_at: string | null;
    findings_count: number;
    high_or_critical_count: number;
    overall_risk_score: number;
  };
  findings: Finding[];
  max_severity_rank: number;
  threshold_triggered: boolean;
  reports: Record<string, string>;
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function severityVariant(severity: string): "danger" | "warning" | "info" | "neutral" {
  if (severity === "CRITICAL" || severity === "HIGH") {
    return "danger";
  }
  if (severity === "MEDIUM") {
    return "warning";
  }
  if (severity === "LOW") {
    return "info";
  }
  return "neutral";
}

function formatDateLabel(iso: string | null): string {
  if (!iso) {
    return "-";
  }
  return new Date(iso).toLocaleString();
}

async function runScan(request: {
  path: string;
  format: OutputFormat;
  fail_on: FailOnSeverity;
}): Promise<ScanResponse> {
  return postJson<ScanResponse, { path: string; format: OutputFormat; fail_on: FailOnSeverity; persist: boolean }>(
    "/api/scan",
    {
      path: request.path,
      format: request.format,
      fail_on: request.fail_on,
      persist: true,
    }
  );
}

export function StaticScanPage() {
  const [targetPath, setTargetPath] = useState("benchmarks/fixtures");
  const [outputFormat, setOutputFormat] = useState<OutputFormat>("both");
  const [failOn, setFailOn] = useState<FailOnSeverity>("high");
  const [verboseView, setVerboseView] = useState(false);

  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [ruleFilter, setRuleFilter] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  const severityBreakdown = useMemo(() => {
    if (!result) {
      return [];
    }
    const counts = new Map<string, number>();
    for (const finding of result.findings) {
      const key = finding.severity.toUpperCase();
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return SEVERITY_ORDER.filter((key) => counts.has(key)).map((key) => ({
      severity: key,
      count: counts.get(key) ?? 0,
    }));
  }, [result]);

  const categoryBreakdown = useMemo(() => {
    if (!result) {
      return [];
    }
    const counts = new Map<string, number>();
    for (const finding of result.findings) {
      counts.set(finding.category, (counts.get(finding.category) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count);
  }, [result]);

  const severityOptions = useMemo(() => severityBreakdown.map((item) => item.severity), [severityBreakdown]);
  const categoryOptions = useMemo(() => categoryBreakdown.map((item) => item.category), [categoryBreakdown]);

  const filteredFindings = useMemo(() => {
    if (!result) {
      return [];
    }
    const normalizedRuleFilter = ruleFilter.trim().toUpperCase();
    return result.findings.filter((finding) => {
      const severityMatch =
        severityFilter === "ALL" || finding.severity.toUpperCase() === severityFilter;
      const categoryMatch = categoryFilter === "ALL" || finding.category === categoryFilter;
      const ruleMatch =
        normalizedRuleFilter.length === 0 ||
        (finding.rule_id ?? "").toUpperCase().includes(normalizedRuleFilter);
      return severityMatch && categoryMatch && ruleMatch;
    });
  }, [result, severityFilter, categoryFilter, ruleFilter]);

  async function executeScan() {
    setError(null);
    setLoading(true);
    try {
      const response = await runScan({
        path: targetPath.trim(),
        format: outputFormat,
        fail_on: failOn,
      });
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run scan.");
    } finally {
      setLoading(false);
    }
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await executeScan();
  }

  return (
    <PageContainer
      title="Static Scan"
      subtitle="Run static checks and inspect findings by severity, category, evidence, and recommendation."
      actions={<Badge variant="neutral">POST /api/scan</Badge>}
    >
      <Card title="Run Static Scan">
        <form className="grid gap-3 md:grid-cols-2" onSubmit={onSubmit}>
          <label className="md:col-span-2">
            <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Target Path</span>
            <input
              className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
              value={targetPath}
              onChange={(event) => setTargetPath(event.target.value)}
              placeholder="benchmarks/fixtures"
              required
            />
          </label>

          <label>
            <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Output Format</span>
            <select
              className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
              value={outputFormat}
              onChange={(event) => setOutputFormat(event.target.value as OutputFormat)}
            >
              <option value="both">both</option>
              <option value="json">json</option>
              <option value="markdown">markdown</option>
            </select>
          </label>

          <label>
            <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Fail-On Severity</span>
            <select
              className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
              value={failOn}
              onChange={(event) => setFailOn(event.target.value as FailOnSeverity)}
            >
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
          </label>

          <label className="inline-flex items-center gap-2 text-sm text-[var(--fg)]">
            <input
              type="checkbox"
              checked={verboseView}
              onChange={(event) => setVerboseView(event.target.checked)}
            />
            Verbose view (show raw response payload)
          </label>

          <div className="md:col-span-2">
            <button
              className="rounded-md border border-teal-700 bg-teal-700 px-3 py-2 text-sm font-medium text-white hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-60"
              type="submit"
              disabled={loading}
            >
              {loading ? "Running..." : "Run Scan"}
            </button>
          </div>
        </form>
      </Card>

      {loading ? <LoadingState label="Running static scan..." /> : null}
      {error ? <ErrorState message={error} onRetry={() => void executeScan()} retryLabel="Run again" /> : null}

      {result ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Card title="Findings Summary">
              <p className="text-2xl font-semibold text-[var(--fg)]">{result.scan_run.findings_count}</p>
              <p className="mt-1 text-xs">
                High/Critical: {result.scan_run.high_or_critical_count} • Risk: {result.scan_run.overall_risk_score}
              </p>
            </Card>

            <Card title="Severity Breakdown">
              <div className="flex flex-wrap gap-1.5">
                {severityBreakdown.length > 0 ? (
                  severityBreakdown.map((item) => (
                    <Badge key={item.severity} variant={severityVariant(item.severity)}>
                      {item.severity}: {item.count}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs">No findings</span>
                )}
              </div>
            </Card>

            <Card title="Category Breakdown">
              <div className="flex flex-wrap gap-1.5">
                {categoryBreakdown.length > 0 ? (
                  categoryBreakdown.map((item) => (
                    <Badge key={item.category} variant="info">
                      {item.category}: {item.count}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs">No findings</span>
                )}
              </div>
            </Card>

            <Card title="Latest Scan Run">
              <p className="text-xs">Started: {formatDateLabel(result.scan_run.started_at)}</p>
              <p className="mt-1 text-xs">Completed: {formatDateLabel(result.scan_run.completed_at)}</p>
              <div className="mt-2">
                <Badge variant={result.threshold_triggered ? "warning" : "success"}>
                  {result.threshold_triggered ? "Threshold Triggered" : "Below Threshold"}
                </Badge>
              </div>
            </Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-2">
            <Card title="Result Artifacts">
              {Object.keys(result.reports).length === 0 ? (
                <EmptyState
                  title="No report artifacts returned"
                  description="Run with json/markdown format to generate output report paths."
                />
              ) : (
                <div className="space-y-2">
                  {Object.entries(result.reports).map(([format, path]) => (
                    <div key={format} className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-2">
                      <p className="text-xs font-medium uppercase text-[var(--fg)]">{format}</p>
                      <code className="mt-1 block break-all text-xs">{path}</code>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {verboseView ? (
              <Card title="Raw API Payload">
                <pre className="max-h-72 overflow-auto rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-2 text-xs text-[var(--fg)]">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </Card>
            ) : null}
          </div>

          <Card title="Filters">
            <div className="grid gap-3 sm:grid-cols-3">
              <label>
                <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Severity</span>
                <select
                  className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
                  value={severityFilter}
                  onChange={(event) => setSeverityFilter(event.target.value)}
                >
                  <option value="ALL">All</option>
                  {severityOptions.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity}
                    </option>
                  ))}
                </select>
              </label>

              <label>
                <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Category</span>
                <select
                  className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
                  value={categoryFilter}
                  onChange={(event) => setCategoryFilter(event.target.value)}
                >
                  <option value="ALL">All</option>
                  {categoryOptions.map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
                </select>
              </label>

              <label>
                <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Rule ID</span>
                <input
                  className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
                  placeholder="EXF-001"
                  value={ruleFilter}
                  onChange={(event) => setRuleFilter(event.target.value)}
                />
              </label>
            </div>
            <div className="mt-3">
              <button
                className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] px-2.5 py-1 text-xs font-medium text-[var(--fg)] hover:bg-white"
                onClick={() => {
                  setSeverityFilter("ALL");
                  setCategoryFilter("ALL");
                  setRuleFilter("");
                }}
                type="button"
              >
                Clear Filters
              </button>
            </div>
          </Card>

          <Card title={`Findings (${filteredFindings.length})`}>
            {filteredFindings.length === 0 ? (
              <EmptyState
                title="No findings match current filters"
                description="Adjust severity, category, or rule-id filters to broaden results."
              />
            ) : (
              <div className="overflow-auto">
                <table className="min-w-[860px] border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[var(--border)] text-[var(--fg)]">
                      <th className="p-2 font-semibold">Severity</th>
                      <th className="p-2 font-semibold">Category</th>
                      <th className="p-2 font-semibold">Rule</th>
                      <th className="p-2 font-semibold">Title</th>
                      <th className="p-2 font-semibold">Evidence</th>
                      <th className="p-2 font-semibold">Recommendation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map((finding) => (
                      <tr key={finding.id} className="border-b border-[var(--border)] align-top">
                        <td className="p-2">
                          <Badge variant={severityVariant(finding.severity.toUpperCase())}>
                            {finding.severity.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="p-2">{finding.category}</td>
                        <td className="p-2">{finding.rule_id ?? "-"}</td>
                        <td className="p-2 text-[var(--fg)]">{finding.title}</td>
                        <td className="max-w-[260px] p-2">
                          <pre className="whitespace-pre-wrap break-words text-xs text-[var(--muted)]">
                            {finding.evidence ?? "-"}
                          </pre>
                        </td>
                        <td className="max-w-[260px] p-2">
                          <pre className="whitespace-pre-wrap break-words text-xs text-[var(--muted)]">
                            {finding.recommendation ?? "-"}
                          </pre>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      ) : null}

      {!loading && !error && !result ? (
        <EmptyState
          title="No static scan run yet"
          description="Submit the form above to run your first static scan and inspect findings."
        />
      ) : null}
    </PageContainer>
  );
}
