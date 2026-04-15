import type { ReactNode } from "react";

type PageContainerProps = {
  title: string;
  subtitle: string;
  actions?: ReactNode;
  children: ReactNode;
};

export function PageContainer({ title, subtitle, actions, children }: PageContainerProps) {
  return (
    <section className="space-y-3 sm:space-y-4">
      <header className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-lg font-semibold tracking-tight sm:text-xl">{title}</h1>
            <p className="mt-1 text-sm text-[var(--muted)]">{subtitle}</p>
          </div>
          {actions ? <div className="w-full sm:w-auto">{actions}</div> : null}
        </div>
      </header>
      <div>{children}</div>
    </section>
  );
}
