import type { ReactNode } from 'react';

export type GlowColor = 'cyan' | 'red' | 'green' | 'amber' | 'purple' | null;

interface Props {
  children: ReactNode;
  className?: string;
  glow?: GlowColor;
  onClick?: () => void;
  selected?: boolean;
}

const GLOW: Record<Exclude<GlowColor, null>, { border: string; shadow: string }> = {
  cyan: { border: 'border-cyan', shadow: 'shadow-glow-cyan' },
  red: { border: 'border-red', shadow: 'shadow-glow-red' },
  green: { border: 'border-green', shadow: 'shadow-glow-green' },
  amber: { border: 'border-amber', shadow: 'shadow-glow-amber' },
  purple: { border: 'border-purple', shadow: 'shadow-glow-purple' },
};

/**
 * The base card used across the app. Angular corner brackets (the four
 * `.tech-corner` spans), a thin border, surface background, and a glow on
 * hover or when a `glow` colour is set.
 */
export function TechCard({ children, className = '', glow = null, onClick, selected = false }: Props) {
  const g = glow ? GLOW[glow] : null;
  const borderCls = g ? g.border : 'border-border';
  const shadowCls = g ? g.shadow : '';
  const interactive = onClick ? 'cursor-pointer' : '';

  return (
    <div
      onClick={onClick}
      className={`group relative border ${borderCls} ${shadowCls} bg-surface transition-all duration-200 hover:border-border-glow hover:shadow-glow-cyan ${
        selected ? 'border-border-glow' : ''
      } ${interactive} ${className}`}
    >
      <span className="tech-corner tech-corner-tl group-hover:!border-[color:var(--accent-cyan)]" />
      <span className="tech-corner tech-corner-tr group-hover:!border-[color:var(--accent-cyan)]" />
      <span className="tech-corner tech-corner-bl group-hover:!border-[color:var(--accent-cyan)]" />
      <span className="tech-corner tech-corner-br group-hover:!border-[color:var(--accent-cyan)]" />
      {children}
    </div>
  );
}
