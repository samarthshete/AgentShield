import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DashboardPage } from "./DashboardPage";

vi.mock("../lib/api", () => ({ fetchJson: vi.fn() }));
import { fetchJson } from "../lib/api";

const mockFetchJson = vi.mocked(fetchJson);

const metrics = {
  metrics: {
    attack_categories: ["TOOL_POISONING"],
    benchmark: { total_cases: 9, passed: 9, failed: 0, pass_rate: 1 },
    dynamic: { scenarios_run: 5, violations_total: 25, categories_covered: ["TASK_DRIFT"] },
    findings_total: 0,
    findings_high_or_critical: 0,
    rule_coverage: { total_rules: 11 },
    eval: {
      total_artifacts: 50,
      false_positives: 2,
      micro_precision: 0.9623,
      micro_recall: 1,
      micro_f1: 0.9808,
      precision_ci: { lower: 0.8725, upper: 0.9896 },
      recall_ci: { lower: 0.93, upper: 1 },
    },
  },
};

afterEach(() => {
  vi.clearAllMocks();
});

describe("DashboardPage", () => {
  it("renders the honest detection-accuracy hero on success", async () => {
    mockFetchJson.mockImplementation((path: string) => {
      if (path.includes("/api/metrics")) return Promise.resolve(metrics as never);
      return Promise.resolve({ runs: [] } as never);
    });

    render(<DashboardPage />);

    await waitFor(() =>
      expect(screen.getByText(/Detection Accuracy/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/F1 98\.1%/)).toBeInTheDocument();
    expect(screen.getByText(/50 labeled artifacts/i)).toBeInTheDocument();
  });

  it("renders an error state when metrics fail to load", async () => {
    mockFetchJson.mockRejectedValue(new Error("API offline"));

    render(<DashboardPage />);

    await waitFor(() => expect(screen.getByText(/API offline/i)).toBeInTheDocument());
  });
});
