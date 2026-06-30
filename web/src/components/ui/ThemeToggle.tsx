import { useEffect, useState } from "react";

import { resolveTheme, setTheme, type Theme } from "../../lib/theme";

export function ThemeToggle() {
  const [theme, setLocalTheme] = useState<Theme>(() => resolveTheme());

  useEffect(() => {
    setTheme(theme);
  }, [theme]);

  const next: Theme = theme === "dark" ? "light" : "dark";

  return (
    <button
      type="button"
      onClick={() => setLocalTheme(next)}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--border)] text-[var(--muted)] transition-colors hover:bg-[var(--surface-muted)] hover:text-[var(--fg)]"
    >
      {theme === "dark" ? (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.4 1.4M17.6 17.6L19 19M19 5l-1.4 1.4M6.4 17.6L5 19" />
        </svg>
      ) : (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" />
        </svg>
      )}
    </button>
  );
}
