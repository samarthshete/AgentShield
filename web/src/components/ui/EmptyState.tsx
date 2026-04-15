type EmptyStateProps = {
  title: string;
  description: string;
};

export function EmptyState({ title, description }: EmptyStateProps) {
  return (
    <div className="rounded-lg border border-dashed border-[var(--border)] bg-[var(--surface-muted)] p-4 text-sm sm:p-5">
      <p className="font-medium text-[var(--fg)]">{title}</p>
      <p className="mt-1 text-[var(--muted)]">{description}</p>
    </div>
  );
}
