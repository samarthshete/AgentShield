import type { ReactNode } from "react";

type StatTileProps = {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: boolean;
};

/** Big-number KPI tile matching the design-system dashboard mockup. */
export function StatTile({ label, value, sub, accent = false }: StatTileProps) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4 shadow-sm">
      <p
        className={`text-2xl font-semibold tracking-tight ${
          accent ? "text-[var(--accent)]" : "text-[var(--fg)]"
        }`}
      >
        {value}
      </p>
      <p className="mt-1 text-xs uppercase tracking-wide text-[var(--muted)]">{label}</p>
      {sub ? <p className="mt-1.5 text-xs text-[var(--faint)]">{sub}</p> : null}
    </div>
  );
}
