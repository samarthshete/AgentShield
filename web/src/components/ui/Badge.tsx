import type { ReactNode } from "react";

type BadgeVariant = "neutral" | "info" | "success" | "warning" | "danger";

const STYLES: Record<BadgeVariant, string> = {
  neutral:
    "border-[var(--sev-info-bd)] bg-[var(--sev-info-bg)] text-[var(--sev-info-fg)]",
  info: "border-[var(--sev-low-bd)] bg-[var(--sev-low-bg)] text-[var(--sev-low-fg)]",
  success:
    "border-[var(--sev-clean-bd)] bg-[var(--sev-clean-bg)] text-[var(--sev-clean-fg)]",
  warning:
    "border-[var(--sev-high-bd)] bg-[var(--sev-high-bg)] text-[var(--sev-high-fg)]",
  danger:
    "border-[var(--sev-critical-bd)] bg-[var(--sev-critical-bg)] text-[var(--sev-critical-fg)]",
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
