import type { ReactNode } from "react";

type BadgeVariant = "neutral" | "info" | "success" | "warning" | "danger";

const STYLES: Record<BadgeVariant, string> = {
  neutral: "border-slate-300 bg-slate-100 text-slate-700",
  info: "border-sky-300 bg-sky-100 text-sky-700",
  success: "border-emerald-300 bg-emerald-100 text-emerald-700",
  warning: "border-amber-300 bg-amber-100 text-amber-700",
  danger: "border-rose-300 bg-rose-100 text-rose-700",
};

type BadgeProps = {
  variant?: BadgeVariant;
  children: ReactNode;
};

export function Badge({ variant = "neutral", children }: BadgeProps) {
  return (
    <span className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${STYLES[variant]}`}>
      {children}
    </span>
  );
}

