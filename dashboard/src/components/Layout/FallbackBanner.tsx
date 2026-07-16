import { useEffect, useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { useApi } from '../../hooks/useApi';
import type { FallbackAlert } from '../../types';

// U0 — surfaces the notifier's local .alert fallback. If every external channel
// (Slack/Discord/PagerDuty) is down, alerts still land here so an operator sees
// them. Polls GET /api/notifications like the rest of the dashboard (10s).
export function FallbackBanner() {
  const api = useApi();
  const [alerts, setAlerts] = useState<FallbackAlert[]>([]);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const a = await api.getNotifications(20);
        if (alive) {
          setAlerts(a);
          if (a.length > 0) setDismissed(false);
        }
      } catch {
        /* API may be down — leave banner as-is */
      }
    };
    load();
    const id = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [api]);

  if (dismissed || alerts.length === 0) return null;
  const latest = alerts[0];

  return (
    <div className="flex shrink-0 items-center gap-2 border-b border-red bg-surface px-4 py-1.5 text-xs">
      <AlertTriangle size={14} className="shrink-0 text-red" />
      <span className="font-mono font-semibold uppercase tracking-wider text-red">Fallback alert</span>
      <span className="min-w-0 flex-1 truncate text-dim">
        {latest.title ?? 'External alerting failed'} — {alerts.length} alert
        {alerts.length > 1 ? 's' : ''} written locally (webhook unreachable)
      </span>
      <button
        onClick={() => setDismissed(true)}
        className="text-dim transition-colors hover:text-primary"
        aria-label="Dismiss"
      >
        <X size={14} />
      </button>
    </div>
  );
}
