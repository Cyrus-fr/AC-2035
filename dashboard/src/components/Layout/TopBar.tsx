import { useEffect, useState } from 'react';
import { useApi } from '../../hooks/useApi';
import type { GraphStats } from '../../types';
import { StatusDot } from '../shared/StatusDot';

interface Props {
  connected: boolean;
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div key={value} className="animate-fade-update flex items-baseline gap-1.5">
      <span className="font-mono text-sm font-semibold text-primary">{value}</span>
      <span className="text-[10px] uppercase tracking-wider text-dim">{label}</span>
    </div>
  );
}

export function TopBar({ connected }: Props) {
  const api = useApi();
  const [stats, setStats] = useState<GraphStats | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const s = await api.getStats();
        if (alive) setStats(s);
      } catch {
        /* graph may be down; leave stats as-is */
      }
    };
    load();
    const id = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [api]);

  return (
    <header className="flex h-12 shrink-0 items-center justify-between border-b border-border bg-surface px-4">
      <div className="flex items-center gap-2">
        <span className="font-mono text-lg font-bold tracking-widest text-cyan [text-shadow:var(--glow-cyan)]">
          AC-2035
        </span>
        <span className="hidden text-[10px] uppercase tracking-wider text-dim sm:inline">
          honeytoken forensic attribution
        </span>
      </div>

      <div className="flex items-center gap-5">
        {stats && (
          <>
            <Stat label="nodes" value={stats.node_count} />
            <Stat label="edges" value={stats.edge_count} />
            <Stat label="tokens" value={stats.honeytoken_count} />
          </>
        )}
      </div>

      <StatusDot status={connected ? 'connected' : 'disconnected'} label={connected ? 'LIVE' : 'OFFLINE'} />
    </header>
  );
}
