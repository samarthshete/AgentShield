import { FormEvent, useMemo, useState } from "react";

import { PageContainer } from "../components/layout/PageContainer";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { postJson } from "../lib/api";

type CategoryBreakdown = {
  total: number;
  passed: number;
  failed: number;
};

type BenchmarkResult = {
  case_id: string;
  case_name: string;
  category: string;
  passed: boolean;
  findings_count: number;
  max_severity: string | null;
  failure_reasons: string[];
};

type BenchmarkResponse = {
  summary: {
    total_cases: number;
    passed: number;
    failed: number;
    pass_rate: number;
    avg_scan_time_ms: number;
    category_breakdown: Record<string, CategoryBreakdown>;
    results: BenchmarkResult[];
  };
  report_path: string;
};

function passRateLabel(rate: number): string {
  return `${Math.round(rate * 100)}%`;
}

async function runBenchmark(payload: {
  suite_dir: string;
  output_dir?: string;
}): Promise<BenchmarkResponse> {
  return postJson<BenchmarkResponse, { suite_dir: string; output_dir?: string }>("/api/benchmark", payload);
}

export function BenchmarkPage() {
  const [suiteDir, setSuiteDir] = useState("benchmarks/cases");
  const [outputDir, setOutputDir] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BenchmarkResponse | null>(null);

  const categoryRows = useMemo(() => {
    if (!result) {
      return [];
    }
    return Object.entries(result.summary.category_breakdown)
      .map(([category, breakdown]) => ({ category, ...breakdown }))
      .sort((a, b) => b.total - a.total);
  }, [result]);

  const failedCases = useMemo(() => {
    if (!result) {
      return [];
    }
    return result.summary.results.filter((item) => !item.passed);
  }, [result]);

  async function executeBenchmark() {
    setLoading(true);
    setError(null);
    try {
      const response = await runBenchmark({
        suite_dir: suiteDir.trim(),
        output_dir: outputDir.trim() || undefined,
      });
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run benchmark.");
    } finally {
      setLoading(false);
    }
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await executeBenchmark();
  }

  return (
    <PageContainer
      title="Benchmarks"
      subtitle="Run benchmark suites and review pass/fail quality across categories."
      actions={<Badge variant="success">POST /api/benchmark</Badge>}
    >
      <Card title="Run Benchmark Suite">
        <form className="grid gap-3 md:grid-cols-2" onSubmit={onSubmit}>
          <label>
            <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Suite Directory</span>
            <input
              className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
              value={suiteDir}
              onChange={(event) => setSuiteDir(event.target.value)}
              placeholder="benchmarks/cases"
              required
            />
          </label>
          <label>
            <span className="mb-1 block text-xs font-medium text-[var(--fg)]">
              Output Directory (optional)
            </span>
            <input
              className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
              value={outputDir}
              onChange={(event) => setOutputDir(event.target.value)}
              placeholder="agentshield-output"
            />
          </label>
          <div className="md:col-span-2">
            <button
              className="rounded-md border border-teal-700 bg-teal-700 px-3 py-2 text-sm font-medium text-white hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-60"
              type="submit"
              disabled={loading}
            >
              {loading ? "Running..." : "Run Benchmarks"}
            </button>
          </div>
        </form>
      </Card>

      {loading ? <LoadingState label="Running benchmark suite..." /> : null}
      {error ? (
        <ErrorState message={error} onRetry={() => void executeBenchmark()} retryLabel="Run again" />
      ) : null}

      {result ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Card title="Total Cases">
              <p className="text-2xl font-semibold text-[var(--fg)]">{result.summary.total_cases}</p>
            </Card>
            <Card title="Passed">
              <p className="text-2xl font-semibold text-emerald-700">{result.summary.passed}</p>
            </Card>
            <Card title="Failed">
              <p className="text-2xl font-semibold text-rose-700">{result.summary.failed}</p>
            </Card>
            <Card title="Pass Rate">
              <p className="text-2xl font-semibold text-[var(--fg)]">
                {passRateLabel(result.summary.pass_rate)}
              </p>
              <p className="mt-1 text-xs">Avg scan time: {result.summary.avg_scan_time_ms.toFixed(1)} ms</p>
            </Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-2">
            <Card title="Category Breakdown">
              {categoryRows.length === 0 ? (
                <EmptyState
                  title="No category breakdown"
                  description="Run a benchmark suite to populate category-level results."
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
                      {categoryRows.map((row) => (
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

            <Card title="Run Artifacts">
              <p className="text-xs text-[var(--muted)]">Benchmark summary JSON path:</p>
              <code className="mt-1 block break-all text-xs text-[var(--fg)]">{result.report_path}</code>
            </Card>
          </div>

          <Card title={`Failed Case Details (${failedCases.length})`}>
            {failedCases.length === 0 ? (
              <EmptyState
                title="No failed cases"
                description="All benchmark cases passed in the latest run."
              />
            ) : (
              <div className="space-y-3">
                {failedCases.map((item) => (
                  <div key={item.case_id} className="rounded-md border border-rose-300 bg-rose-50 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <code className="text-xs text-rose-700">{item.case_id}</code>
                      <Badge variant="danger">failed</Badge>
                      <Badge variant="neutral">{item.category}</Badge>
                    </div>
                    <p className="mt-1 text-sm font-medium text-rose-800">{item.case_name}</p>
                    <p className="mt-1 text-xs text-rose-700">
                      Findings: {item.findings_count} • Max severity: {item.max_severity ?? "-"}
                    </p>
                    <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-rose-700">
                      {item.failure_reasons.length > 0 ? (
                        item.failure_reasons.map((reason, index) => <li key={index}>{reason}</li>)
                      ) : (
                        <li>No failure reason details returned.</li>
                      )}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </>
      ) : null}

      {!loading && !error && !result ? (
        <EmptyState
          title="No benchmark run yet"
          description="Run the benchmark suite to see pass rate, category breakdown, and failed case details."
        />
      ) : null}
    </PageContainer>
  );
}
