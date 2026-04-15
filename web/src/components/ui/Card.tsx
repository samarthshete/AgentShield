import type { ReactNode } from "react";

type CardProps = {
  title?: string;
  children: ReactNode;
};

export function Card({ title, children }: CardProps) {
  return (
    <article className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4 shadow-sm sm:p-5">
      {title ? <h2 className="mb-3 text-sm font-semibold text-[var(--fg)]">{title}</h2> : null}
      <div className="text-sm text-[var(--muted)]">{children}</div>
    </article>
  );
}
