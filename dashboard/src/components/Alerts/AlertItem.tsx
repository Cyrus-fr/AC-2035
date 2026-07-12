import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import type { Alert } from '../../types';
import { GlowBadge, type BadgeVariant } from '../shared/GlowBadge';

const BADGE: Record<string, { variant: BadgeVariant; label: string }> = {
  honeytoken_trigger: { variant: 'red', label: 'TRIGGERED' },
  killswitch_fired: { variant: 'amber', label: 'KILL-SWITCH' },
  token_rotated: { variant: 'green', label: 'ROTATED' },
  system_info: { variant: 'cyan', label: 'SYSTEM' },
  connected: { variant: 'cyan', label: 'SYSTEM' },
};

function summarize(alert: Alert): string {
  const d = alert.data ?? {};
  switch (alert.type) {
    case 'honeytoken_trigger':
      return `entry ${d.entry_point ?? '—'} · confidence ${d.confidence ?? '—'} · kill-switch ${d.killswitch_status ?? '—'}`;
    case 'killswitch_fired':
      return `status ${d.status ?? '—'} · by ${d.triggered_by ?? '—'}`;
    case 'token_rotated':
      return `${d.rotated ?? 0} token(s) rotated`;
    case 'system_info':
    case 'connected':
      return String(d.message ?? alert.message ?? 'system event');
    default:
      return alert.message ?? '';
  }
}

export function AlertItem({ alert }: { alert: Alert }) {
  const [expanded, setExpanded] = useState(false);
  const badge = BADGE[alert.type] ?? { variant: 'grey' as BadgeVariant, label: alert.type.toUpperCase() };
  const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '--:--:--';

  return (
    <div className="animate-slide-in-top border-b border-border/60 px-3 py-2 hover:bg-elevated/40">
      <div className="flex cursor-pointer items-center gap-2" onClick={() => setExpanded((v) => !v)}>
        {expanded ? (
          <ChevronDown className="h-3 w-3 shrink-0 text-dim" />
        ) : (
          <ChevronRight className="h-3 w-3 shrink-0 text-dim" />
        )}
        <span className="font-mono text-[11px] text-dim">{ts}</span>
        <GlowBadge variant={badge.variant} label={badge.label} />
        {alert.token_id && (
          <span className="font-mono text-[11px] text-secondary">{alert.token_id.slice(0, 8)}</span>
        )}
        <span className="truncate text-xs text-primary">{summarize(alert)}</span>
      </div>
      {expanded && (
        <pre className="mt-2 max-h-48 overflow-auto border border-border bg-base p-2 font-mono text-[10px] text-secondary">
          {JSON.stringify(alert, null, 2)}
        </pre>
      )}
    </div>
  );
}
