import { useMemo, useState } from 'react';
import type { Alert } from '../../types';
import { StatusDot } from '../shared/StatusDot';
import { AlertItem } from './AlertItem';

interface Props {
  messages: Alert[];
  connected: boolean;
}

type Filter = 'ALL' | 'TRIGGERED' | 'KILL-SWITCH' | 'ROTATED' | 'SYSTEM';

const FILTER_TYPE: Record<Exclude<Filter, 'ALL'>, string> = {
  TRIGGERED: 'honeytoken_trigger',
  'KILL-SWITCH': 'killswitch_fired',
  ROTATED: 'token_rotated',
  SYSTEM: 'system_info',
};

export function AlertFeed({ messages, connected }: Props) {
  const [filter, setFilter] = useState<Filter>('ALL');
  // Soft clear: hide everything at/older than the marker (newest at clear time).
  const [clearMarker, setClearMarker] = useState<Alert | null>(null);

  const visible = useMemo(() => {
    let list = messages;
    if (clearMarker) {
      const idx = messages.indexOf(clearMarker);
      list = idx >= 0 ? messages.slice(0, idx) : messages; // marker aged off the cap → show all
    }
    if (filter === 'ALL') return list;
    const wanted = FILTER_TYPE[filter];
    return list.filter((m) => m.type === wanted || (filter === 'SYSTEM' && m.type === 'connected'));
  }, [messages, filter, clearMarker]);

  const last = messages[0];

  return (
    <div className="flex h-full flex-col">
      {/* filter bar */}
      <div className="flex items-center gap-2 border-b border-border bg-surface px-3 py-2">
        {(['ALL', 'TRIGGERED', 'KILL-SWITCH', 'ROTATED', 'SYSTEM'] as Filter[]).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`border px-2 py-1 font-mono text-[10px] uppercase tracking-wider transition-all ${
              filter === f
                ? 'border-cyan text-cyan shadow-glow-cyan'
                : 'border-border text-secondary hover:text-primary'
            }`}
          >
            {f}
          </button>
        ))}
        <button
          onClick={() => setClearMarker(messages[0] ?? null)}
          className="ml-auto border border-border px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-dim transition-colors hover:text-red"
        >
          Clear
        </button>
      </div>

      {/* feed */}
      <div className="flex-1 overflow-y-auto font-mono">
        {visible.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-dim">
            awaiting alerts…
          </div>
        ) : (
          visible.map((m, i) => <AlertItem key={`${m.timestamp}-${i}`} alert={m} />)
        )}
      </div>

      {/* status bar */}
      <div className="flex items-center justify-between border-t border-border bg-surface px-3 py-2">
        <StatusDot
          status={connected ? 'connected' : 'disconnected'}
          label={connected ? 'stream connected' : 'stream offline'}
        />
        <span className="font-mono text-[10px] text-dim">
          {last?.timestamp ? `last: ${new Date(last.timestamp).toLocaleTimeString()}` : 'no messages'}
        </span>
      </div>
    </div>
  );
}
