const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

const COLOR: Record<string, string> = {
  CRITICAL: "var(--sev-critical-fg)",
  HIGH: "var(--sev-high-fg)",
  MEDIUM: "var(--sev-medium-fg)",
  LOW: "var(--sev-low-fg)",
  INFO: "var(--sev-info-fg)",
};

type SeverityBarProps = {
  counts: Record<string, number>;
};

/** Horizontal stacked severity-distribution bar with a legend (color-blind-safe labels). */
export function SeverityBar({ counts }: SeverityBarProps) {
  const entries = ORDER.map((s) => [s, counts[s] ?? 0] as const).filter(([, c]) => c > 0);
  const total = entries.reduce((sum, [, c]) => sum + c, 0);

  if (total === 0) {
    return <p className="text-xs text-[var(--muted)]">No findings</p>;
  }

  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-[var(--surface-muted)]">
        {entries.map(([severity, count]) => (
          <div
            key={severity}
            style={{ flexGrow: count, backgroundColor: COLOR[severity] }}
            title={`${severity}: ${count}`}
          />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs">
        {entries.map(([severity, count]) => (
          <span key={severity} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: COLOR[severity] }} />
            <span className="text-[var(--muted)]">
              {severity} {count}
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}
