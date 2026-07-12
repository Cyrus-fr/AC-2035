import { useEffect, useState } from 'react';
import { Crosshair, Maximize2, RefreshCw, Trash2 } from 'lucide-react';
import { useGraph } from '../../hooks/useGraph';
import { NodeDetail } from './NodeDetail';

export function AttackGraph() {
  const graph = useGraph();
  const [attackToken, setAttackToken] = useState('');

  // Load the full graph once the container (and thus cy) is mounted.
  useEffect(() => {
    const t = setTimeout(() => graph.refresh(), 50);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="relative h-full w-full overflow-hidden">
      <div ref={graph.containerRef} className="absolute inset-0" />

      {graph.loading && (
        <div className="absolute left-4 top-4 z-10 font-mono text-xs text-cyan">loading graph…</div>
      )}
      {graph.error && (
        <div className="absolute left-4 top-4 z-10 max-w-md border border-red bg-surface px-3 py-2 font-mono text-xs text-red shadow-glow-red">
          {graph.error}
        </div>
      )}
      {!graph.loading && !graph.error && graph.nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center font-mono text-sm text-dim">
          graph is empty — trigger an attack or ingest a timeline
        </div>
      )}

      {/* Floating controls */}
      <div className="absolute bottom-4 right-4 z-10 w-64 space-y-2 border border-border bg-surface/95 p-3 backdrop-blur">
        <div className="flex gap-2">
          <button
            onClick={graph.refresh}
            className="flex flex-1 items-center justify-center gap-1 border border-border bg-elevated py-1.5 text-xs text-cyan transition-all hover:border-cyan hover:shadow-glow-cyan"
          >
            <RefreshCw className="h-3 w-3" /> Load
          </button>
          <button
            onClick={graph.clear}
            className="flex flex-1 items-center justify-center gap-1 border border-border bg-elevated py-1.5 text-xs text-red transition-all hover:border-red hover:shadow-glow-red"
          >
            <Trash2 className="h-3 w-3" /> Clear
          </button>
          <button
            onClick={graph.fit}
            className="flex flex-1 items-center justify-center gap-1 border border-border bg-elevated py-1.5 text-xs text-secondary transition-all hover:border-border-glow hover:text-primary"
          >
            <Maximize2 className="h-3 w-3" /> Fit
          </button>
        </div>
        <div className="flex gap-2">
          <input
            value={attackToken}
            onChange={(e) => setAttackToken(e.target.value)}
            placeholder="token_id"
            className="min-w-0 flex-1 border border-border bg-base px-2 py-1.5 font-mono text-xs text-primary placeholder:text-dim focus:border-border-glow focus:outline-none"
          />
          <button
            onClick={() => attackToken && graph.loadAttackPath(attackToken.trim())}
            className="flex items-center gap-1 border border-amber bg-elevated px-2 py-1.5 text-xs text-amber transition-all hover:shadow-glow-amber"
          >
            <Crosshair className="h-3 w-3" /> Trace
          </button>
        </div>
      </div>

      <NodeDetail node={graph.selectedNode} onClose={graph.clearSelection} />
    </div>
  );
}
