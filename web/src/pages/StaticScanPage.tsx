import { FormEvent, useMemo, useState } from "react";

import { PageContainer } from "../components/layout/PageContainer";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { SeverityBar } from "../components/ui/SeverityBar";
import { StatTile } from "../components/ui/StatTile";
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

function severityBorderColor(severity: string): string {
  const map: Record<string, string> = {
    CRITICAL: "var(--sev-critical-fg)",
    HIGH: "var(--sev-high-fg)",
    MEDIUM: "var(--sev-medium-fg)",
    LOW: "var(--sev-low-fg)",
    INFO: "var(--sev-info-fg)",
  };
  return map[severity.toUpperCase()] ?? "transparent";
}

function formatDateLabel(iso: string | null): string {
  if (!iso) {
    return "-";
  }
  return new Date(iso).toLocaleString();
}

type InputMode = "path" | "paste";

type ScanRequestBody = {
  path?: string;
  content?: string;
  filename?: string;
  format: OutputFormat;
  fail_on: FailOnSeverity;
  persist: boolean;
};

async function runScan(request: {
  path?: string;
  content?: string;
  filename?: string;
  format: OutputFormat;
  fail_on: FailOnSeverity;
}): Promise<ScanResponse> {
  const body: ScanRequestBody = {
    format: request.format,
    fail_on: request.fail_on,
    persist: true,
  };
  if (request.content && request.content.trim()) {
    body.content = request.content;
    body.filename = request.filename?.trim() || "pasted-config.txt";
  } else {
    body.path = request.path;
  }
  return postJson<ScanResponse, ScanRequestBody>("/api/scan", body);
}

export function StaticScanPage() {
  const [inputMode, setInputMode] = useState<InputMode>("path");
  const [targetPath, setTargetPath] = useState("benchmarks/fixtures");
  const [pastedContent, setPastedContent] = useState("");
  const [pastedFilename, setPastedFilename] = useState("agent.json");
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
        path: inputMode === "path" ? targetPath.trim() : undefined,
        content: inputMode === "paste" ? pastedContent : undefined,
        filename: pastedFilename,
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
          <div className="md:col-span-2 inline-flex w-fit rounded-md border border-[var(--border)] p-0.5 text-sm">
            <button
              type="button"
              onClick={() => setInputMode("path")}
              className={`rounded px-3 py-1 ${inputMode === "path" ? "bg-[var(--accent)] text-[var(--accent-fg)]" : "text-[var(--muted)]"}`}
            >
              Server path
            </button>
            <button
              type="button"
              onClick={() => setInputMode("paste")}
              className={`rounded px-3 py-1 ${inputMode === "paste" ? "bg-[var(--accent)] text-[var(--accent-fg)]" : "text-[var(--muted)]"}`}
            >
              Paste config
            </button>
          </div>

          {inputMode === "path" ? (
            <label className="md:col-span-2">
              <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Target Path</span>
              <input
                className="w-full rounded-md border border-[var(--border)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--fg)]"
                value={targetPath}
                onChange={(event) => setTargetPath(event.target.value)}
                placeholder="benchmarks/fixtures"
              />
            </label>
          ) : (
            <>
              <label className="md:col-span-2">
                <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Filename (for context)</span>
                <input
                  className="w-full rounded-md border border-[var(--border)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--fg)]"
                  value={pastedFilename}
                  onChange={(event) => setPastedFilename(event.target.value)}
                  placeholder="agent.json"
                />
              </label>
              <label className="md:col-span-2">
                <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Config content</span>
                <textarea
                  className="h-40 w-full rounded-md border border-[var(--border)] bg-[var(--field)] px-3 py-2 font-mono text-xs text-[var(--fg)]"
                  value={pastedContent}
                  onChange={(event) => setPastedContent(event.target.value)}
                  placeholder={'{\n  "tools": [\n    { "name": "run", "description": "..." }\n  ]\n}'}
                />
              </label>
            </>
          )}

          <label>
            <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Output Format</span>
            <select
              className="w-full rounded-md border border-[var(--border)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--fg)]"
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
              className="w-full rounded-md border border-[var(--border)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--fg)]"
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
              className="rounded-md border border-[var(--accent)] bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--accent-fg)] hover:bg-[var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
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
            <StatTile label="Findings" value={result.scan_run.findings_count} />
            <StatTile
              label="High / Critical"
              value={result.scan_run.high_or_critical_count}
              accent={result.scan_run.high_or_critical_count > 0}
              sub="needs review"
            />
            <StatTile label="Risk score" value={result.scan_run.overall_risk_score} sub="/ 100 weighted" />
            <Card title="Severity Breakdown">
              <SeverityBar
                counts={Object.fromEntries(severityBreakdown.map((i) => [i.severity, i.count]))}
              />
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
                  className="w-full rounded-md border border-[var(--border)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--fg)]"
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
                  className="w-full rounded-md border border-[var(--border)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--fg)]"
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
                  className="w-full rounded-md border border-[var(--border)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--fg)]"
                  placeholder="EXF-001"
                  value={ruleFilter}
                  onChange={(event) => setRuleFilter(event.target.value)}
                />
              </label>
            </div>
            <div className="mt-3">
              <button
                className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] px-2.5 py-1 text-xs font-medium text-[var(--fg)] hover:bg-[var(--field)]"
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
                        <td
                          className="p-2"
                          style={{ borderLeft: `3px solid ${severityBorderColor(finding.severity)}` }}
                        >
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
