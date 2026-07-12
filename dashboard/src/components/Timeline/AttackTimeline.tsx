import { useEffect, useMemo, useState } from 'react';
import { Clock, Play } from 'lucide-react';
import { useApi } from '../../hooks/useApi';
import type { CyEdge, Token } from '../../types';

// The API exposes the reconstructed graph, not raw telemetry, so a token's
// timeline is derived from its attack-path edges — each edge is a timed
// interaction. Edge relationship types map to the telemetry colours.
const EDGE_COLOR: Record<string, { color: string; label: string }> = {
  CONNECTED_TO: { color: 'var(--accent-cyan)', label: 'network' },
  MOVED_TO: { color: 'var(--accent-red)', label: 'lateral' },
  ACCESSED: { color: 'var(--accent-amber)', label: 'access' },
  TRIGGERED: { color: 'var(--accent-red)', label: 'trigger' },
};

interface Tick {
  edge: CyEdge['data'];
  pos: number; // 0..1 across the timeline
  isTrigger: boolean;
}

export function AttackTimeline() {
  const api = useApi();
  const [tokens, setTokens] = useState<Token[]>([]);
  const [selected, setSelected] = useState('');
  const [edges, setEdges] = useState<CyEdge['data'][]>([]);
  const [error, setError] = useState<string | null>(null);
  const [hover, setHover] = useState<Tick | null>(null);

  useEffect(() => {
    api
      .getTokens()
      .then((t) => {
        setTokens(t);
        if (t.length && !selected) setSelected(t[0].token_id);
      })
      .catch(() => setTokens([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api]);

  const load = async () => {
    if (!selected) return;
    setError(null);
    const data = await api.getAttackPath(selected);
    if (!data) {
      setEdges([]);
      setError(`No attack path / timeline for ${selected}`);
      return;
    }
    const withTs = data.edges.map((e) => e.data).filter((d) => d.timestamp);
    withTs.sort((a, b) => (a.timestamp! < b.timestamp! ? -1 : 1));
    setEdges(withTs);
  };

  const ticks = useMemo<Tick[]>(() => {
    if (edges.length === 0) return [];
    const times = edges.map((e) => new Date(e.timestamp!).getTime());
    const min = Math.min(...times);
    const max = Math.max(...times);
    const span = max - min || 1;
    return edges.map((e, i) => ({
      edge: e,
      pos: (new Date(e.timestamp!).getTime() - min) / span,
      isTrigger: e.type === 'ACCESSED' || i === edges.length - 1,
    }));
  }, [edges]);

  return (
    <div className="flex h-full flex-col p-4">
      <div className="mb-4 flex items-center gap-2">
        <Clock className="h-4 w-4 text-cyan" />
        <select
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          className="border border-border bg-base px-2 py-1.5 font-mono text-xs text-primary focus:border-border-glow focus:outline-none"
        >
          <option value="">select token…</option>
          {tokens.map((t) => (
            <option key={t.token_id} value={t.token_id}>
              {t.token_id.slice(0, 8)} · {t.status}
            </option>
          ))}
        </select>
        <button
          onClick={load}
          disabled={!selected}
          className="flex items-center gap-1.5 border border-cyan bg-elevated px-3 py-1.5 text-xs text-cyan transition-all hover:shadow-glow-cyan disabled:opacity-50"
        >
          <Play className="h-3 w-3" /> Load Timeline
        </button>
      </div>

      {error && <div className="mb-3 font-mono text-xs text-amber">{error}</div>}

      {/* timeline track */}
      <div className="relative mb-6 h-24 border border-border bg-surface">
        <div className="absolute left-0 top-1/2 h-px w-full -translate-y-1/2 bg-border" />
        {ticks.map((t, i) => {
          const cfg = EDGE_COLOR[t.edge.type] ?? { color: 'var(--text-dim)', label: t.edge.type };
          return (
            <div
              key={i}
              className="absolute top-1/2 -translate-x-1/2 -translate-y-1/2"
              style={{ left: `${5 + t.pos * 90}%` }}
              onMouseEnter={() => setHover(t)}
              onMouseLeave={() => setHover(null)}
            >
              <div
                className={`h-8 w-[3px] ${t.isTrigger ? 'animate-glow-pulse' : ''}`}
                style={{ background: t.isTrigger ? 'var(--accent-red)' : cfg.color }}
              />
            </div>
          );
        })}
        {ticks.length === 0 && (
          <div className="flex h-full items-center justify-center font-mono text-xs text-dim">
            no timeline loaded
          </div>
        )}
        {hover && (
          <div className="absolute -top-2 left-1/2 z-10 -translate-x-1/2 -translate-y-full border border-border-glow bg-overlay p-2 font-mono text-[10px] text-primary shadow-glow-cyan">
            <div>{hover.edge.type}</div>
            <div className="text-dim">{hover.edge.timestamp}</div>
            <div>
              {hover.edge.source} → {hover.edge.target}
            </div>
            {hover.edge.cf_ray && <div>cf_ray: {hover.edge.cf_ray}</div>}
            {hover.edge.confidence && <div>confidence: {hover.edge.confidence}</div>}
          </div>
        )}
      </div>

      {/* event table */}
      <div className="flex-1 overflow-y-auto border border-border">
        <table className="w-full border-collapse font-mono text-[11px]">
          <thead className="sticky top-0 bg-elevated text-dim">
            <tr>
              {['Time', 'Type', 'Source → Dest', 'CF-Ray', 'Confidence'].map((h) => (
                <th key={h} className="border-b border-border px-3 py-2 text-left uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {edges.map((e, i) => (
              <tr key={i} className="text-secondary hover:bg-elevated/40">
                <td className="px-3 py-1.5 text-dim">{e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—'}</td>
                <td className="px-3 py-1.5" style={{ color: (EDGE_COLOR[e.type] ?? { color: '' }).color }}>
                  {e.type}
                </td>
                <td className="px-3 py-1.5 text-primary">
                  {e.source} → {e.target}
                </td>
                <td className="px-3 py-1.5">{e.cf_ray ?? '—'}</td>
                <td className="px-3 py-1.5">{e.confidence ?? '—'}</td>
              </tr>
            ))}
            {edges.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-dim">
                  select a token and load its timeline
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
