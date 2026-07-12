import { useCallback, useEffect, useState } from 'react';
import { RotateCw } from 'lucide-react';
import { useApi } from '../../hooks/useApi';
import type { Token } from '../../types';
import { TokenCard } from './TokenCard';

type Filter = 'ALL' | 'ACTIVE' | 'TRIGGERED' | 'ROTATED';
const FILTER_STATUS: Record<Exclude<Filter, 'ALL'>, string> = {
  ACTIVE: 'active',
  TRIGGERED: 'triggered',
  ROTATED: 'rotated',
};

export function TokenBoard() {
  const api = useApi();
  const [tokens, setTokens] = useState<Token[]>([]);
  const [filter, setFilter] = useState<Filter>('ALL');
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setTokens(await api.getTokens());
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [api]);

  useEffect(() => {
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, [load]);

  const rotateAll = async () => {
    setRotating(true);
    try {
      await api.rotateTokens();
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRotating(false);
    }
  };

  const visible = filter === 'ALL' ? tokens : tokens.filter((t) => t.status === FILTER_STATUS[filter]);

  return (
    <div className="flex h-full flex-col p-4">
      <div className="mb-4 flex items-center gap-2">
        {(['ALL', 'ACTIVE', 'TRIGGERED', 'ROTATED'] as Filter[]).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`border px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider transition-all ${
              filter === f ? 'border-cyan text-cyan shadow-glow-cyan' : 'border-border text-secondary hover:text-primary'
            }`}
          >
            {f}
          </button>
        ))}
        <button
          onClick={rotateAll}
          disabled={rotating}
          className="ml-auto flex items-center gap-1.5 border border-amber bg-elevated px-3 py-1.5 text-xs text-amber transition-all hover:shadow-glow-amber disabled:opacity-50"
        >
          <RotateCw className={`h-3.5 w-3.5 ${rotating ? 'animate-spin' : ''}`} /> Rotate All
        </button>
      </div>

      {error && (
        <div className="mb-3 border border-red bg-surface px-3 py-2 font-mono text-xs text-red">{error}</div>
      )}

      <div className="flex-1 overflow-y-auto">
        {visible.length === 0 ? (
          <div className="flex h-full items-center justify-center font-mono text-sm text-dim">
            no tokens {filter !== 'ALL' ? `with status ${filter.toLowerCase()}` : 'in registry'}
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {visible.map((t) => (
              <TokenCard key={t.token_id} token={t} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
