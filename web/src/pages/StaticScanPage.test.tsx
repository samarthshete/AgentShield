import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { StaticScanPage } from "./StaticScanPage";

vi.mock("../lib/api", () => ({ postJson: vi.fn() }));
import { postJson } from "../lib/api";

const mockPostJson = vi.mocked(postJson);

afterEach(() => {
  vi.clearAllMocks();
});

describe("StaticScanPage", () => {
  it("renders the empty state before any scan", () => {
    render(<StaticScanPage />);
    expect(screen.getByText(/No static scan run yet/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /run scan/i })).toBeInTheDocument();
  });

  it("renders findings after a successful scan", async () => {
    mockPostJson.mockResolvedValue({
      scan_run: {
        id: "1",
        started_at: new Date().toISOString(),
        completed_at: null,
        findings_count: 1,
        high_or_critical_count: 1,
        overall_risk_score: 50,
      },
      findings: [
        {
          id: "f1",
          category: "DATA_EXFILTRATION_PATTERN",
          severity: "CRITICAL",
          title: "Strong exfiltration signal",
          evidence: "api key",
          recommendation: "Keep secrets in the trust boundary.",
          rule_id: "EXF-001",
          affected_component: "agent.json",
        },
      ],
      max_severity_rank: 5,
      threshold_triggered: true,
      reports: {},
    } as never);

    render(<StaticScanPage />);
    fireEvent.click(screen.getByRole("button", { name: /run scan/i }));

    await waitFor(() =>
      expect(screen.getByText(/Strong exfiltration signal/i)).toBeInTheDocument(),
    );
    expect(screen.getByText("EXF-001")).toBeInTheDocument();
  });

  it("renders an error state when the scan fails", async () => {
    mockPostJson.mockRejectedValue(new Error("Unauthorized (401) — set a valid API token"));

    render(<StaticScanPage />);
    fireEvent.click(screen.getByRole("button", { name: /run scan/i }));

    await waitFor(() =>
      expect(screen.getByText(/Unauthorized \(401\)/i)).toBeInTheDocument(),
    );
  });
});
