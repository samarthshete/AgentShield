type LoadingStateProps = {
  label?: string;
};

export function LoadingState({ label = "Loading..." }: LoadingStateProps) {
  return (
    <div
      className="rounded-lg border border-dashed border-[var(--border)] bg-[var(--surface-muted)] p-4"
      role="status"
      aria-live="polite"
    >
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 animate-pulse rounded-full bg-[var(--accent)]" />
        <span className="text-sm text-[var(--muted)]">{label}</span>
      </div>
    </div>
  );
}
