import { useCallback, useEffect, useState } from 'react';
import { Check, X } from 'lucide-react';
import { useApi } from '../../hooks/useApi';
import type { KillSwitchAction, KillSwitchResult, PendingItem } from '../../types';
import { GlowBadge, type BadgeVariant } from '../shared/GlowBadge';
import { PendingApprovals } from './PendingApprovals';

const STATUS_VARIANT: Record<string, BadgeVariant> = {
  executed: 'green',
  partial: 'amber',
  failed: 'red',
  pending: 'amber',
};

function ActionRow({ action }: { action: KillSwitchAction }) {
  const short = action.action_type.replace(/_/g, ' ');
  return (
    <div className="flex items-center gap-2 font-mono text-[11px]">
      {action.success ? (
        <Check className="h-3 w-3 text-green" />
      ) : (
        <X className="h-3 w-3 text-red" />
      )}
      <span className="text-secondary">{short}</span>
      <span className="text-dim">— {action.error ?? 'ok'}</span>
    </div>
  );
}

export function KillSwitchPanel() {
  const api = useApi();
  const [pending, setPending] = useState<PendingItem[]>([]);
  const [audit, setAudit] = useState<KillSwitchResult[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());

  const refresh = useCallback(async () => {
    try {
      const [p, a] = await Promise.all([api.getPending(), api.getAlerts(50)]);
      setPending(p);
      setAudit(a);
    } catch {
      /* backend may be momentarily unavailable */
    }
  }, [api]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 10000);
    return () => clearInterval(id);
  }, [refresh]);

  const approve = async (pendingId: string) => {
    await api.approve(pendingId);
    await refresh();
  };

  const dismiss = (pendingId: string) => setDismissed((s) => new Set(s).add(pendingId));

  const visiblePending = pending.filter((p) => !dismissed.has(p.pending_id));

  return (
    <div className="grid h-full grid-cols-1 gap-4 overflow-hidden p-4 lg:grid-cols-2">
      {/* LEFT — pending approvals */}
      <div className="flex min-h-0 flex-col">
        <div className="mb-3 flex items-center gap-2">
          <span className="font-mono text-xs uppercase tracking-widest text-amber">Pending Approvals</span>
          {visiblePending.length > 0 && (
            <span className="font-mono text-[10px] text-dim">({visiblePending.length})</span>
          )}
        </div>
        <div className="flex-1 overflow-y-auto pr-1">
          <PendingApprovals pending={visiblePending} onApprove={approve} onDismiss={dismiss} />
        </div>
      </div>

      {/* RIGHT — audit log */}
      <div className="flex min-h-0 flex-col border-l border-border pl-4">
        <div className="mb-3 font-mono text-xs uppercase tracking-widest text-cyan">Audit Log</div>
        <div className="flex-1 space-y-3 overflow-y-auto pr-1">
          {audit.length === 0 ? (
            <div className="flex h-full items-center justify-center font-mono text-sm text-dim">
              no kill-switch history
            </div>
          ) : (
            audit.map((r, i) => (
              <div key={`${r.attack_object_token_id}-${i}`} className="border border-border bg-surface p-3">
                <div className="flex items-center justify-between">
                  <GlowBadge variant={STATUS_VARIANT[r.status] ?? 'grey'} label={r.status} />
                  <span className="font-mono text-[10px] text-dim">
                    {r.executed_at ? new Date(r.executed_at).toLocaleString() : '—'}
                  </span>
                </div>
                <div className="mt-1.5 font-mono text-[11px] text-secondary">
                  {r.attack_object_token_id.slice(0, 8)} · {r.triggered_by}
                </div>
                <div className="mt-2 space-y-1 border-t border-border pt-2">
                  {r.actions.map((a, j) => (
                    <ActionRow key={j} action={a} />
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
