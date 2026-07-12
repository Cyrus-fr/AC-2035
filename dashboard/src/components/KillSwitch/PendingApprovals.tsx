import { Check, Shield, X } from 'lucide-react';
import type { PendingItem } from '../../types';
import { GlowBadge, type BadgeVariant } from '../shared/GlowBadge';
import { TechCard } from '../shared/TechCard';

interface Props {
  pending: PendingItem[];
  onApprove: (pendingId: string) => void;
  onDismiss: (pendingId: string) => void;
}

function confVariant(c?: string | null): BadgeVariant {
  if (c === 'high') return 'green';
  if (c === 'medium') return 'amber';
  return 'red';
}

export function PendingApprovals({ pending, onApprove, onDismiss }: Props) {
  if (pending.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-dim">
        <Shield className="h-10 w-10 opacity-40" />
        <span className="font-mono text-sm">No pending approvals</span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {pending.map((p) => (
        <TechCard key={p.pending_id} glow="amber" className="animate-glow-pulse p-3">
          <div className="flex items-center justify-between">
            <span className="font-mono text-sm text-primary">{(p.token_id ?? p.pending_id).slice(0, 8)}</span>
            <GlowBadge variant={confVariant(p.confidence)} label={p.confidence ?? 'unknown'} />
          </div>
          <div className="mt-1.5 font-mono text-[11px] text-secondary">
            entry: {p.entry_point ?? '—'}
          </div>
          <div className="mt-3 flex gap-2">
            <button
              onClick={() => onApprove(p.pending_id)}
              className="flex flex-1 items-center justify-center gap-1 border border-red bg-elevated py-1.5 text-xs text-red transition-all hover:shadow-glow-red"
            >
              <Check className="h-3 w-3" /> APPROVE
            </button>
            <button
              onClick={() => onDismiss(p.pending_id)}
              className="flex flex-1 items-center justify-center gap-1 border border-border bg-elevated py-1.5 text-xs text-secondary transition-colors hover:text-primary"
            >
              <X className="h-3 w-3" /> DISMISS
            </button>
          </div>
        </TechCard>
      ))}
    </div>
  );
}
