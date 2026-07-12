import { X } from 'lucide-react';
import type { CyNode } from '../../types';
import { GlowBadge, type BadgeVariant } from '../shared/GlowBadge';

interface Props {
  node: CyNode['data'] | null;
  onClose: () => void;
}

function typeVariant(type: string): BadgeVariant {
  switch (type) {
    case 'ExternalIP':
      return 'red';
    case 'Pod':
      return 'cyan';
    case 'Honeytoken':
      return 'amber';
    case 'Identity':
      return 'purple';
    default:
      return 'grey';
  }
}

export function NodeDetail({ node, onClose }: Props) {
  if (!node) return null;
  const props = node.properties ?? {};

  return (
    <div className="animate-slide-in-right absolute right-0 top-0 z-20 h-full w-[320px] border-l border-border-glow bg-surface/95 backdrop-blur">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <GlowBadge variant={typeVariant(node.type)} label={node.type} />
        <button onClick={onClose} className="text-secondary transition-colors hover:text-primary" title="Close">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="space-y-3 p-4">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-dim">label</div>
          <div className="break-all font-mono text-sm text-primary">{node.label}</div>
        </div>

        {node.attack_path && <GlowBadge variant="red" label="ON ATTACK PATH" />}

        <div className="border-t border-border pt-3">
          <div className="mb-2 text-[10px] uppercase tracking-wider text-dim">properties</div>
          <div className="space-y-2">
            {Object.entries(props).length === 0 && (
              <div className="text-xs text-dim">No properties</div>
            )}
            {Object.entries(props).map(([k, v]) => (
              <div key={k} className="flex flex-col">
                <span className="text-[10px] uppercase tracking-wider text-secondary">{k}</span>
                <span className="break-all font-mono text-xs text-primary">
                  {k === 'token_value' ? '••••••••' : String(v)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
