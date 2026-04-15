import { useCallback, useEffect, useMemo, useState } from "react";

import { PageContainer } from "../components/layout/PageContainer";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { fetchJson } from "../lib/api";

type RuleInfo = {
  rule_id: string;
  category: string;
  severity: string;
};

type MetricsPayload = {
  metrics: {
    generated_at: string;
    agentshield_version: string;
    attack_categories: string[];
    total_test_cases: number;
    benchmark: {
      total_cases: number;
      passed: number;
      failed: number;
      pass_rate: number;
      avg_scan_time_ms: number;
      p95_scan_time_ms: number;
      category_breakdown: Record<string, { total: number; passed: number; failed: number }>;
    };
    dynamic: {
      scenarios_run: number;
      violations_total: number;
      categories_covered: string[];
      max_severity_seen: string | null;
    };
    rule_coverage: {
      total_rules: number;
      rules_by_category: Record<string, string[]>;
      all_rules: RuleInfo[];
    };
    workflows_or_configs_scanned: number;
    findings_total: number;
    findings_high_or_critical: number;
    avg_scan_time_seconds: number;
    p95_scan_time_seconds: number;
    rules_only_rate: number;
    llm_routing_rate: number;
    avg_scan_cost_usd: number;
  };
};

function percentLabel(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function formatDateLabel(iso: string): string {
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

async function loadMetrics(): Promise<MetricsPayload> {
  return fetchJson<MetricsPayload>("/api/metrics");
}

export function MetricsPage() {
  const [data, setData] = useState<MetricsPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await loadMetrics();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load metrics.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchMetrics();
  }, [fetchMetrics]);

  const benchmarkCategoryRows = useMemo(() => {
    if (!data) {
      return [];
    }
    return Object.entries(data.metrics.benchmark.category_breakdown)
      .map(([category, values]) => ({ category, ...values }))
      .sort((a, b) => b.total - a.total);
  }, [data]);

  const rulesByCategoryRows = useMemo(() => {
    if (!data) {
      return [];
    }
    return Object.entries(data.metrics.rule_coverage.rules_by_category)
      .map(([category, rules]) => ({ category, rules }))
      .sort((a, b) => a.category.localeCompare(b.category));
  }, [data]);

  return (
    <PageContainer
      title="Metrics"
      subtitle="Project-level metrics across attack coverage, rule inventory, benchmarks, and dynamic simulation."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <button
            className="rounded-md border border-[var(--border)] bg-[var(--surface)] px-2.5 py-1 text-xs font-medium text-[var(--fg)] hover:bg-[var(--surface-muted)]"
            onClick={() => void fetchMetrics()}
          >
            Refresh
          </button>
          <Badge variant="info">GET /api/metrics</Badge>
        </div>
      }
    >
      {loading ? <LoadingState label="Loading project metrics..." /> : null}
      {error ? <ErrorState message={error} onRetry={() => void fetchMetrics()} /> : null}

      {!loading && !error && data ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Card title="Attack Categories">
              <p className="text-2xl font-semibold text-[var(--fg)]">{data.metrics.attack_categories.length}</p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {data.metrics.attack_categories.map((category) => (
                  <Badge key={category} variant="neutral">
                    {category}
                  </Badge>
                ))}
              </div>
            </Card>

            <Card title="Rule Inventory">
              <p className="text-2xl font-semibold text-[var(--fg)]">{data.metrics.rule_coverage.total_rules}</p>
              <p className="mt-1 text-xs">Rules discovered by runtime registry probe.</p>
            </Card>

            <Card title="Benchmark Stats">
              <p className="text-xl font-semibold text-[var(--fg)]">
                {data.metrics.benchmark.passed}/{data.metrics.benchmark.total_cases} passed
              </p>
              <p className="mt-1 text-xs">
                Pass rate {percentLabel(data.metrics.benchmark.pass_rate)} • Failed {data.metrics.benchmark.failed}
              </p>
              <p className="mt-1 text-xs">
                Avg {data.metrics.benchmark.avg_scan_time_ms.toFixed(1)} ms • P95{" "}
                {data.metrics.benchmark.p95_scan_time_ms.toFixed(1)} ms
              </p>
            </Card>

            <Card title="Dynamic Stats">
              <p className="text-xl font-semibold text-[var(--fg)]">
                {data.metrics.dynamic.scenarios_run} scenarios
              </p>
              <p className="mt-1 text-xs">
                Violations {data.metrics.dynamic.violations_total} • Max severity{" "}
                {data.metrics.dynamic.max_severity_seen ?? "-"}
              </p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {data.metrics.dynamic.categories_covered.map((category) => (
                  <Badge key={category} variant="info">
                    {category}
                  </Badge>
                ))}
              </div>
            </Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-2">
            <Card title="Project Summary Metrics">
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">Generated</p>
                  <p className="mt-1 text-xs">{formatDateLabel(data.metrics.generated_at)}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">Version</p>
                  <p className="mt-1 text-xs">{data.metrics.agentshield_version}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">Configs Scanned</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg)]">
                    {data.metrics.workflows_or_configs_scanned}
                  </p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">Findings Total</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg)]">{data.metrics.findings_total}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">Findings High/Critical</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg)]">
                    {data.metrics.findings_high_or_critical}
                  </p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">Total Test Cases</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg)]">{data.metrics.total_test_cases}</p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">Avg Scan Time</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg)]">
                    {data.metrics.avg_scan_time_seconds.toFixed(2)} s
                  </p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">P95 Scan Time</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg)]">
                    {data.metrics.p95_scan_time_seconds.toFixed(2)} s
                  </p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">Rules Only Rate</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg)]">
                    {percentLabel(data.metrics.rules_only_rate)}
                  </p>
                </div>
                <div>
                  <p className="text-xs font-medium text-[var(--fg)]">LLM Routing Rate</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg)]">
                    {percentLabel(data.metrics.llm_routing_rate)}
                  </p>
                </div>
              </div>
            </Card>

            <Card title="Rule Coverage by Category">
              {rulesByCategoryRows.length === 0 ? (
                <EmptyState
                  title="No rule coverage data"
                  description="Metrics response did not include rule coverage rows."
                />
              ) : (
                <div className="overflow-auto">
                  <table className="min-w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-[var(--border)] text-[var(--fg)]">
                        <th className="p-2 font-semibold">Category</th>
                        <th className="p-2 font-semibold">Rules</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rulesByCategoryRows.map((row) => (
                        <tr key={row.category} className="border-b border-[var(--border)] align-top">
                          <td className="p-2">{row.category}</td>
                          <td className="p-2">
                            <div className="flex flex-wrap gap-1.5">
                              {row.rules.map((ruleId) => (
                                <Badge key={ruleId} variant="neutral">
                                  {ruleId}
                                </Badge>
                              ))}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>

          <Card title="Rule Inventory (11 Rules)">
            {data.metrics.rule_coverage.all_rules.length === 0 ? (
              <EmptyState title="No rule inventory" description="No rule rows found in metrics payload." />
            ) : (
              <div className="overflow-auto">
                <table className="min-w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[var(--border)] text-[var(--fg)]">
                      <th className="p-2 font-semibold">Rule ID</th>
                      <th className="p-2 font-semibold">Category</th>
                      <th className="p-2 font-semibold">Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.metrics.rule_coverage.all_rules.map((rule) => (
                      <tr key={rule.rule_id} className="border-b border-[var(--border)]">
                        <td className="p-2">
                          <code>{rule.rule_id}</code>
                        </td>
                        <td className="p-2">{rule.category}</td>
                        <td className="p-2">
                          <Badge variant={severityVariant(rule.severity)}>{rule.severity}</Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card title="Benchmark Category Breakdown">
            {benchmarkCategoryRows.length === 0 ? (
              <EmptyState
                title="No benchmark category breakdown"
                description="Metrics response did not include benchmark category rows."
              />
            ) : (
              <div className="overflow-auto">
                <table className="min-w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[var(--border)] text-[var(--fg)]">
                      <th className="p-2 font-semibold">Category</th>
                      <th className="p-2 font-semibold">Total</th>
                      <th className="p-2 font-semibold">Passed</th>
                      <th className="p-2 font-semibold">Failed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {benchmarkCategoryRows.map((row) => (
                      <tr key={row.category} className="border-b border-[var(--border)]">
                        <td className="p-2">{row.category}</td>
                        <td className="p-2">{row.total}</td>
                        <td className="p-2 text-emerald-700">{row.passed}</td>
                        <td className="p-2 text-rose-700">{row.failed}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      ) : null}

      {!loading && !error && !data ? (
        <EmptyState
          title="No metrics loaded"
          description="Trigger a refresh to fetch project-level metrics from the backend."
        />
      ) : null}
    </PageContainer>
  );
}
