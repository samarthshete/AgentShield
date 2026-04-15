import { useCallback, useEffect, useMemo, useState } from "react";

import { PageContainer } from "../components/layout/PageContainer";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { fetchJson } from "../lib/api";

type MetricsResponse = {
  metrics: {
    attack_categories: string[];
    benchmark: {
      total_cases: number;
      passed: number;
      failed: number;
      pass_rate: number;
    };
    dynamic: {
      scenarios_run: number;
      violations_total: number;
      categories_covered: string[];
    };
    findings_total: number;
    findings_high_or_critical: number;
    rule_coverage: {
      total_rules: number;
    };
  };
};

type ScanHistoryResponse = {
  runs: Array<{
    id: string;
    started_at: string;
    findings_count: number;
    high_or_critical_count: number;
    overall_risk_score: number;
  }>;
};

type DynamicHistoryResponse = {
  runs: Array<{
    id: string;
    scenario_id: string;
    ran_at: string;
    violation_count: number;
    raw_violation_count: number;
    passed_clean: boolean;
    judge_type: string;
    judge_model: string | null;
  }>;
};

type DashboardPayload = {
  metrics: MetricsResponse["metrics"];
  scans: ScanHistoryResponse["runs"];
  dynamicRuns: DynamicHistoryResponse["runs"];
};

function formatPassRate(rate: number): string {
  return `${Math.round(rate * 100)}%`;
}

function formatDateLabel(iso: string): string {
  return new Date(iso).toLocaleString();
}

function compareIsoDesc(a: string, b: string): number {
  return new Date(b).getTime() - new Date(a).getTime();
}

export function DashboardPage() {
  const [data, setData] = useState<DashboardPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<string | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [metrics, scans, dynamic] = await Promise.all([
        fetchJson<MetricsResponse>("/api/metrics"),
        fetchJson<ScanHistoryResponse>("/api/history/scans?limit=5"),
        fetchJson<DynamicHistoryResponse>("/api/history/dynamic?limit=25"),
      ]);
      setData({
        metrics: metrics.metrics,
        scans: scans.runs,
        dynamicRuns: dynamic.runs,
      });
      setLastRefreshedAt(new Date().toISOString());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const latestRunSummary = useMemo(() => {
    if (!data) {
      return null;
    }
    const latestScan = data.scans[0];
    const latestDynamic = [...data.dynamicRuns].sort((a, b) => compareIsoDesc(a.ran_at, b.ran_at))[0];

    if (!latestScan && !latestDynamic) {
      return null;
    }
    if (latestScan && !latestDynamic) {
      return {
        label: "Latest: Static Scan",
        at: latestScan.started_at,
        line1: `${latestScan.findings_count} findings`,
        line2: `High/Critical ${latestScan.high_or_critical_count} • Risk ${latestScan.overall_risk_score}`,
      };
    }
    if (!latestScan && latestDynamic) {
      return {
        label: "Latest: Dynamic Simulation",
        at: latestDynamic.ran_at,
        line1: `${latestDynamic.violation_count}/${latestDynamic.raw_violation_count} confirmed/raw violations`,
        line2: `${latestDynamic.scenario_id} • ${latestDynamic.passed_clean ? "clean" : "violations found"}`,
      };
    }

    const scanTime = new Date(latestScan.started_at).getTime();
    const dynamicTime = new Date(latestDynamic.ran_at).getTime();
    if (scanTime >= dynamicTime) {
      return {
        label: "Latest: Static Scan",
        at: latestScan.started_at,
        line1: `${latestScan.findings_count} findings`,
        line2: `High/Critical ${latestScan.high_or_critical_count} • Risk ${latestScan.overall_risk_score}`,
      };
    }
    return {
      label: "Latest: Dynamic Simulation",
      at: latestDynamic.ran_at,
      line1: `${latestDynamic.violation_count}/${latestDynamic.raw_violation_count} confirmed/raw violations`,
      line2: `${latestDynamic.scenario_id} • ${latestDynamic.passed_clean ? "clean" : "violations found"}`,
    };
  }, [data]);

  const judgeSummary = useMemo(() => {
    if (!data || data.dynamicRuns.length === 0) {
      return null;
    }
    const counts: Record<string, number> = {};
    for (const run of data.dynamicRuns) {
      counts[run.judge_type] = (counts[run.judge_type] ?? 0) + 1;
    }
    const latest = [...data.dynamicRuns].sort((a, b) => compareIsoDesc(a.ran_at, b.ran_at))[0];
    return {
      counts,
      latestType: latest.judge_type,
      latestModel: latest.judge_model,
      latestAt: latest.ran_at,
    };
  }, [data]);

  const dynamicSummary = useMemo(() => {
    if (!data) {
      return null;
    }
    const dirtyRuns = data.dynamicRuns.filter((run) => !run.passed_clean).length;
    return {
      totalRuns: data.dynamicRuns.length,
      dirtyRuns,
      scenariosRun: data.metrics.dynamic.scenarios_run,
      violationsTotal: data.metrics.dynamic.violations_total,
      categoriesCovered: data.metrics.dynamic.categories_covered,
    };
  }, [data]);

  return (
    <PageContainer
      title="Dashboard"
      subtitle="First-look security posture across attack coverage, rules, benchmarks, dynamic simulations, and recent runs."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          {lastRefreshedAt ? (
            <span className="text-xs text-[var(--muted)]">Updated {formatDateLabel(lastRefreshedAt)}</span>
          ) : null}
          <button
            className="rounded-md border border-[var(--border)] bg-[var(--surface)] px-2.5 py-1 text-xs font-medium text-[var(--fg)] hover:bg-[var(--surface-muted)]"
            onClick={() => void loadDashboard()}
          >
            Refresh
          </button>
        </div>
      }
    >
      {loading ? <LoadingState label="Loading dashboard data..." /> : null}
      {error ? <ErrorState message={error} onRetry={() => void loadDashboard()} /> : null}
      {!loading && !error && data ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          <Card title="Attack Categories Covered">
            <p className="text-2xl font-semibold text-[var(--fg)]">{data.metrics.attack_categories.length}</p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {data.metrics.attack_categories.map((category) => (
                <Badge key={category} variant="neutral">
                  {category}
                </Badge>
              ))}
            </div>
          </Card>

          <Card title="Rule Count">
            <p className="text-2xl font-semibold text-[var(--fg)]">{data.metrics.rule_coverage.total_rules}</p>
            <p className="mt-1 text-xs">Rules active in current static policy set.</p>
          </Card>

          <Card title="Benchmark Pass Rate">
            <p className="text-2xl font-semibold text-[var(--fg)]">
              {formatPassRate(data.metrics.benchmark.pass_rate)}
            </p>
            <p className="mt-1 text-xs">
              {data.metrics.benchmark.passed}/{data.metrics.benchmark.total_cases} cases passed
            </p>
            {data.metrics.benchmark.failed > 0 ? (
              <div className="mt-2">
                <Badge variant="warning">{data.metrics.benchmark.failed} failed</Badge>
              </div>
            ) : null}
          </Card>

          <Card title="Dynamic Scenario Summary">
            {dynamicSummary ? (
              <>
                <p className="text-2xl font-semibold text-[var(--fg)]">{dynamicSummary.scenariosRun}</p>
                <p className="mt-1 text-xs">
                  Scenarios run • {dynamicSummary.violationsTotal} confirmed violations total
                </p>
                <p className="mt-2 text-xs">
                  Recent runs: {dynamicSummary.totalRuns} ({dynamicSummary.dirtyRuns} with violations)
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {dynamicSummary.categoriesCovered.map((category) => (
                    <Badge key={category} variant="info">
                      {category}
                    </Badge>
                  ))}
                </div>
              </>
            ) : (
              <EmptyState
                title="No dynamic summary"
                description="Run simulation scenarios to populate this card."
              />
            )}
          </Card>

          <Card title="Latest Run Summary">
            {latestRunSummary ? (
              <>
                <p className="text-sm font-semibold text-[var(--fg)]">{latestRunSummary.label}</p>
                <p className="mt-1 text-xs">{formatDateLabel(latestRunSummary.at)}</p>
                <p className="mt-2 text-sm">{latestRunSummary.line1}</p>
                <p className="mt-1 text-xs">{latestRunSummary.line2}</p>
              </>
            ) : (
              <EmptyState
                title="No runs yet"
                description="Execute a scan or simulation to show recent activity."
              />
            )}
          </Card>

          <Card title="Judge / Provider Summary">
            {judgeSummary ? (
              <>
                <p className="text-sm font-semibold text-[var(--fg)]">
                  Latest judge: {judgeSummary.latestType}
                  {judgeSummary.latestModel ? ` (${judgeSummary.latestModel})` : ""}
                </p>
                <p className="mt-1 text-xs">{formatDateLabel(judgeSummary.latestAt)}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {Object.entries(judgeSummary.counts).map(([judgeType, count]) => (
                    <Badge key={judgeType} variant={judgeType === "rule_based" ? "neutral" : "success"}>
                      {judgeType}: {count}
                    </Badge>
                  ))}
                </div>
              </>
            ) : (
              <EmptyState
                title="No judge metadata yet"
                description="Run dynamic simulations to capture judge/provider details."
              />
            )}
          </Card>
        </div>
      ) : null}
      {!loading && !error && !data ? (
        <EmptyState title="No dashboard data" description="Dashboard data is unavailable right now." />
      ) : null}
    </PageContainer>
  );
}
