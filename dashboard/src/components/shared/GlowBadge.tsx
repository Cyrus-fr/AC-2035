import type { ReactNode } from 'react';

export type BadgeVariant = 'red' | 'green' | 'cyan' | 'amber' | 'purple' | 'grey';

interface Props {
  variant: BadgeVariant;
  label: string;
  icon?: ReactNode;
}

const VARIANT: Record<BadgeVariant, { text: string; border: string; shadow: string }> = {
  red: { text: 'text-red', border: 'border-red', shadow: 'shadow-glow-red' },
  green: { text: 'text-green', border: 'border-green', shadow: 'shadow-glow-green' },
  cyan: { text: 'text-cyan', border: 'border-cyan', shadow: 'shadow-glow-cyan' },
  amber: { text: 'text-amber', border: 'border-amber', shadow: 'shadow-glow-amber' },
  purple: { text: 'text-purple', border: 'border-purple', shadow: 'shadow-glow-purple' },
  grey: { text: 'text-secondary', border: 'border-border-glow', shadow: '' },
};

export function GlowBadge({ variant, label, icon }: Props) {
  const v = VARIANT[variant];
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border bg-elevated font-mono text-[10px] uppercase tracking-wider ${v.text} ${v.border} ${v.shadow}`}
    >
      {icon}
      {label}
    </span>
  );
}
