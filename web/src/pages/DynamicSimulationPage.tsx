import { FormEvent, useMemo, useState } from "react";

import { PageContainer } from "../components/layout/PageContainer";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { postJson } from "../lib/api";

type JudgeType = "rule_based" | "openai" | "claude";
type ScenarioOption =
  | "all"
  | "DYN-TP-001"
  | "DYN-IPI-001"
  | "DYN-EXF-001"
  | "DYN-UP-001"
  | "DYN-TD-001";

type PolicyViolation = {
  policy_id: string;
  category: string;
  severity: string;
  title: string;
  evidence: string;
  step_seq: number | null;
  recommendation: string;
};

type ScenarioResult = {
  scenario_id: string;
  scenario_name: string;
  category: string;
  violations: PolicyViolation[];
  raw_violations: PolicyViolation[];
  dismissed_violations: PolicyViolation[];
  violation_count: number;
  max_severity: string | null;
  passed_clean: boolean;
  judge_type: string;
  judge_model: string | null;
  trace: {
    scenario_id: string;
    scenario_name: string;
    category: string;
    steps: Array<{
      seq: number;
      role: string;
      content: string;
      flagged: boolean;
    }>;
  };
};

type SimulateResponse = {
  scenarios: ScenarioResult[];
  total_scenarios: number;
  dirty_scenarios: number;
  reports: Record<string, string>;
};

const SCENARIO_OPTIONS: Array<{ value: ScenarioOption; label: string }> = [
  { value: "all", label: "all scenarios" },
  { value: "DYN-TP-001", label: "DYN-TP-001 tool poisoning" },
  { value: "DYN-IPI-001", label: "DYN-IPI-001 indirect prompt injection" },
  { value: "DYN-EXF-001", label: "DYN-EXF-001 data exfiltration pattern" },
  { value: "DYN-UP-001", label: "DYN-UP-001 unsafe permissions" },
  { value: "DYN-TD-001", label: "DYN-TD-001 task drift" },
];

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

async function runSimulation(payload: {
  scenario: ScenarioOption;
  judge: JudgeType;
  llm_model: string;
}): Promise<SimulateResponse> {
  return postJson<
    SimulateResponse,
    { scenario: ScenarioOption; judge: JudgeType; llm_model: string; persist: boolean }
  >("/api/simulate", {
      scenario: payload.scenario,
      judge: payload.judge,
      llm_model: payload.llm_model,
      persist: true,
  });
}

function ViolationList({
  title,
  items,
  emptyTitle,
  emptyDescription,
}: {
  title: string;
  items: PolicyViolation[];
  emptyTitle: string;
  emptyDescription: string;
}) {
  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold uppercase tracking-wide text-[var(--fg)]">{title}</p>
      {items.length === 0 ? (
        <EmptyState title={emptyTitle} description={emptyDescription} />
      ) : (
        <div className="space-y-2">
          {items.map((violation, index) => (
            <div key={`${violation.policy_id}-${index}`} className="rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={severityVariant(violation.severity)}>{violation.severity}</Badge>
                <code className="text-xs text-[var(--fg)]">{violation.policy_id}</code>
                {violation.step_seq !== null ? (
                  <Badge variant="neutral">step {violation.step_seq}</Badge>
                ) : null}
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
  );
}

export function DynamicSimulationPage() {
  const [scenario, setScenario] = useState<ScenarioOption>("all");
  const [judge, setJudge] = useState<JudgeType>("rule_based");
  const [model, setModel] = useState("");
  const [verboseView, setVerboseView] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SimulateResponse | null>(null);

  const hasJudgeModelInput = judge !== "rule_based";

  const totals = useMemo(() => {
    if (!result) {
      return null;
    }
    const raw = result.scenarios.reduce((sum, scenarioResult) => sum + scenarioResult.raw_violations.length, 0);
    const confirmed = result.scenarios.reduce((sum, scenarioResult) => sum + scenarioResult.violations.length, 0);
    const dismissed = result.scenarios.reduce(
      (sum, scenarioResult) => sum + scenarioResult.dismissed_violations.length,
      0
    );
    return { raw, confirmed, dismissed };
  }, [result]);

  async function executeSimulation() {
    setLoading(true);
    setError(null);
    try {
      const response = await runSimulation({
        scenario,
        judge,
        llm_model: hasJudgeModelInput ? model.trim() : "",
      });
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run dynamic simulation.");
    } finally {
      setLoading(false);
    }
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await executeSimulation();
  }

  return (
    <PageContainer
      title="Dynamic Simulation"
      subtitle="Execute adversarial scenarios, compare raw policy output with confirmed and dismissed judge outcomes, and inspect per-scenario violations."
      actions={<Badge variant="warning">POST /api/simulate</Badge>}
    >
      <Card title="Run Simulation">
        <form className="grid gap-3 md:grid-cols-2" onSubmit={onSubmit}>
          <label>
            <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Scenario</span>
            <select
              className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
              value={scenario}
              onChange={(event) => setScenario(event.target.value as ScenarioOption)}
            >
              {SCENARIO_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span className="mb-1 block text-xs font-medium text-[var(--fg)]">Judge</span>
            <select
              className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
              value={judge}
              onChange={(event) => setJudge(event.target.value as JudgeType)}
            >
              <option value="rule_based">rule_based</option>
              <option value="openai">openai</option>
              <option value="claude">claude</option>
            </select>
          </label>

          {hasJudgeModelInput ? (
            <label className="md:col-span-2">
              <span className="mb-1 block text-xs font-medium text-[var(--fg)]">
                Model (optional override)
              </span>
              <input
                className="w-full rounded-md border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--fg)]"
                value={model}
                onChange={(event) => setModel(event.target.value)}
                placeholder={judge === "openai" ? "e.g. gpt-4o-mini" : "e.g. claude-3-5-haiku-latest"}
              />
            </label>
          ) : null}

          <label className="inline-flex items-center gap-2 text-sm text-[var(--fg)]">
            <input
              type="checkbox"
              checked={verboseView}
              onChange={(event) => setVerboseView(event.target.checked)}
            />
            Verbose view (show raw payload + traces)
          </label>

          <div className="md:col-span-2">
            <button
              className="rounded-md border border-teal-700 bg-teal-700 px-3 py-2 text-sm font-medium text-white hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-60"
              type="submit"
              disabled={loading}
            >
              {loading ? "Running..." : "Run Simulation"}
            </button>
          </div>
        </form>
      </Card>

      {loading ? <LoadingState label="Running dynamic simulation..." /> : null}
      {error ? (
        <ErrorState message={error} onRetry={() => void executeSimulation()} retryLabel="Run again" />
      ) : null}

      {result && totals ? (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            <Card title="Raw Violations">
              <p className="text-2xl font-semibold text-[var(--fg)]">{totals.raw}</p>
              <p className="mt-1 text-xs">Policy engine output before judge filtering.</p>
            </Card>
            <Card title="Confirmed Violations">
              <p className="text-2xl font-semibold text-emerald-700">{totals.confirmed}</p>
              <p className="mt-1 text-xs">Actionable violations retained by the selected judge.</p>
            </Card>
            <Card title="Dismissed Violations">
              <p className="text-2xl font-semibold text-amber-700">{totals.dismissed}</p>
              <p className="mt-1 text-xs">Raw violations dismissed by judge review.</p>
            </Card>
          </div>

          <Card title="Run Summary">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">Scenarios Executed</p>
                <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{result.total_scenarios}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">Scenarios with Violations</p>
                <p className="mt-1 text-lg font-semibold text-[var(--fg)]">{result.dirty_scenarios}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">JSON Report</p>
                <code className="mt-1 block break-all text-xs">{result.reports.json ?? "-"}</code>
              </div>
              <div>
                <p className="text-xs font-medium text-[var(--fg)]">Markdown Report</p>
                <code className="mt-1 block break-all text-xs">{result.reports.markdown ?? "-"}</code>
              </div>
            </div>
          </Card>

          <div className="space-y-4">
            {result.scenarios.map((scenarioResult) => {
              const rawCount = scenarioResult.raw_violations.length;
              const confirmedCount = scenarioResult.violations.length;
              const dismissedCount = scenarioResult.dismissed_violations.length;

              return (
                <Card
                  key={scenarioResult.scenario_id}
                  title={`${scenarioResult.scenario_id} • ${scenarioResult.scenario_name}`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="info">{scenarioResult.category}</Badge>
                    <Badge variant={scenarioResult.passed_clean ? "success" : "warning"}>
                      {scenarioResult.passed_clean ? "clean" : "violations detected"}
                    </Badge>
                    <Badge variant="neutral">judge: {scenarioResult.judge_type}</Badge>
                    {scenarioResult.judge_model ? (
                      <Badge variant="neutral">model: {scenarioResult.judge_model}</Badge>
                    ) : null}
                    <Badge variant={scenarioResult.max_severity ? severityVariant(scenarioResult.max_severity) : "neutral"}>
                      max severity: {scenarioResult.max_severity ?? "-"}
                    </Badge>
                  </div>

                  <div className="mt-3 grid gap-2 sm:grid-cols-3">
                    <div className="rounded-md border border-slate-300 bg-slate-50 p-2 text-center">
                      <p className="text-xs uppercase text-slate-700">Raw</p>
                      <p className="text-xl font-semibold text-slate-800">{rawCount}</p>
                    </div>
                    <div className="rounded-md border border-emerald-300 bg-emerald-50 p-2 text-center">
                      <p className="text-xs uppercase text-emerald-700">Confirmed</p>
                      <p className="text-xl font-semibold text-emerald-700">{confirmedCount}</p>
                    </div>
                    <div className="rounded-md border border-amber-300 bg-amber-50 p-2 text-center">
                      <p className="text-xs uppercase text-amber-700">Dismissed</p>
                      <p className="text-xl font-semibold text-amber-700">{dismissedCount}</p>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-4 xl:grid-cols-2">
                    <ViolationList
                      title="Confirmed Violations"
                      items={scenarioResult.violations}
                      emptyTitle="No confirmed violations"
                      emptyDescription="This scenario is currently clean under the selected judge."
                    />
                    <ViolationList
                      title="Dismissed Violations"
                      items={scenarioResult.dismissed_violations}
                      emptyTitle="No dismissed violations"
                      emptyDescription="Judge did not dismiss any raw findings for this scenario."
                    />
                  </div>

                  {verboseView ? (
                    <div className="mt-4 space-y-2">
                      <p className="text-xs font-semibold uppercase tracking-wide text-[var(--fg)]">
                        Raw Violations
                      </p>
                      <pre className="max-h-80 overflow-auto rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-2 text-xs text-[var(--fg)]">
                        {JSON.stringify(scenarioResult.raw_violations, null, 2)}
                      </pre>
                      <p className="text-xs font-semibold uppercase tracking-wide text-[var(--fg)]">
                        Trace
                      </p>
                      <pre className="max-h-80 overflow-auto rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-2 text-xs text-[var(--fg)]">
                        {JSON.stringify(scenarioResult.trace, null, 2)}
                      </pre>
                    </div>
                  ) : null}
                </Card>
              );
            })}
          </div>

          {verboseView ? (
            <Card title="Raw API Payload">
              <pre className="max-h-96 overflow-auto rounded-md border border-[var(--border)] bg-[var(--surface-muted)] p-2 text-xs text-[var(--fg)]">
                {JSON.stringify(result, null, 2)}
              </pre>
            </Card>
          ) : null}
        </>
      ) : null}

      {!loading && !error && !result ? (
        <EmptyState
          title="No simulation run yet"
          description="Use the controls above to run one or all scenarios and inspect raw vs confirmed vs dismissed outcomes."
        />
      ) : null}
    </PageContainer>
  );
}
