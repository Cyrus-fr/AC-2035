import { useState } from 'react';
import type { Token, TokenStatus } from '../../types';
import { GlowBadge } from '../shared/GlowBadge';
import { StatusDot } from '../shared/StatusDot';
import { TechCard, type GlowColor } from '../shared/TechCard';

const STATUS_GLOW: Record<TokenStatus, GlowColor> = {
  active: 'green',
  triggered: 'red',
  rotated: 'amber',
  expired: null,
};

function fmt(ts: string | null): string {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export function TokenCard({ token }: { token: Token }) {
  const [expanded, setExpanded] = useState(false);
  const glow = token.status === 'active' || token.status === 'triggered' ? STATUS_GLOW[token.status] : null;
  const pulse = token.status === 'triggered' ? 'animate-glow-pulse' : '';

  return (
    <TechCard glow={glow} onClick={() => setExpanded((v) => !v)} className={`p-3 ${pulse}`}>
      <div className="flex items-center justify-between">
        <span className="font-mono text-sm text-primary">{token.token_id.slice(0, 8)}</span>
        <StatusDot status={token.status} showLabel={false} />
      </div>

      <div className="mt-2 flex items-center gap-2">
        <GlowBadge variant="purple" label={token.token_type} />
      </div>
      <div className="mt-1.5 font-mono text-[11px] text-secondary">
        {token.target_namespace ?? '—'} / {token.target_pod ?? '—'}
      </div>

      <div className="mt-3 border-t border-border pt-2 font-mono text-[10px] text-dim">
        <div>injected: {fmt(token.injected_at)}</div>
        <div>rotated: {fmt(token.last_rotated_at)}</div>
      </div>

      {expanded && (
        <div className="mt-2 space-y-1 border-t border-border pt-2 font-mono text-[10px] text-secondary">
          <div>token_id: {token.token_id}</div>
          <div>secret_path: {token.secret_manager_path ?? '—'}</div>
          <div>status: {token.status}</div>
          {/* token_value is never rendered. */}
          <div>value: ••••••••</div>
        </div>
      )}
    </TechCard>
  );
}
