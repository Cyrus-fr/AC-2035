import { Activity, Clock, GitBranch, PanelLeftClose, PanelLeftOpen, Shield, Zap } from 'lucide-react';
import type { ViewId } from '../../types';

interface Props {
  active: ViewId;
  onSelect: (view: ViewId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

const NAV: { id: ViewId; label: string; icon: typeof GitBranch }[] = [
  { id: 'graph', label: 'Attack Graph', icon: GitBranch },
  { id: 'alerts', label: 'Alert Feed', icon: Activity },
  { id: 'tokens', label: 'Token Board', icon: Shield },
  { id: 'timeline', label: 'Attack Timeline', icon: Clock },
  { id: 'killswitch', label: 'Kill-Switch', icon: Zap },
];

export function Sidebar({ active, onSelect, collapsed, onToggleCollapse }: Props) {
  return (
    <aside
      className={`shrink-0 border-r border-border bg-surface transition-all duration-200 ${
        collapsed ? 'w-[60px]' : 'w-[220px]'
      }`}
    >
      <nav className="flex h-full flex-col py-3">
        {NAV.map(({ id, label, icon: Icon }) => {
          const isActive = id === active;
          return (
            <button
              key={id}
              onClick={() => onSelect(id)}
              title={label}
              className={`relative flex items-center gap-3 px-4 py-3 text-left transition-colors ${
                isActive ? 'text-cyan' : 'text-secondary hover:text-primary'
              }`}
            >
              {isActive && (
                <span className="absolute left-0 top-0 h-full w-[2px] bg-cyan shadow-glow-cyan" />
              )}
              <Icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span className="text-sm font-medium">{label}</span>}
            </button>
          );
        })}

        <button
          onClick={onToggleCollapse}
          title={collapsed ? 'Expand' : 'Collapse'}
          className="mt-auto flex items-center gap-3 px-4 py-3 text-dim transition-colors hover:text-secondary"
        >
          {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          {!collapsed && <span className="text-xs">Collapse</span>}
        </button>
      </nav>
    </aside>
  );
}
