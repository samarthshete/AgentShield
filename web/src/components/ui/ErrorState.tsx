type ErrorStateProps = {
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
};

export function ErrorState({ message, onRetry, retryLabel = "Retry" }: ErrorStateProps) {
  return (
    <div
      className="rounded-lg border border-[var(--sev-critical-bd)] bg-[var(--sev-critical-bg)] p-4 text-sm text-[var(--sev-critical-fg)]"
      role="alert"
    >
      <p className="font-medium">Request Error</p>
      <p className="mt-1">{message}</p>
      {onRetry ? (
        <button
          className="mt-3 rounded-md border border-[var(--sev-critical-bd)] bg-[var(--surface)] px-2.5 py-1 text-xs font-medium text-[var(--sev-critical-fg)] hover:bg-[var(--sev-critical-bg)]"
          onClick={onRetry}
          type="button"
        >
          {retryLabel}
        </button>
      ) : null}
    </div>
  );
}
