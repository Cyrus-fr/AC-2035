export type DotStatus =
  | 'active'
  | 'triggered'
  | 'rotated'
  | 'expired'
  | 'connected'
  | 'disconnected'
  | 'pending';

interface Props {
  status: DotStatus;
  label?: string;
  showLabel?: boolean;
}

const CONFIG: Record<DotStatus, { color: string; shadow: string; pulse: boolean }> = {
  active: { color: 'bg-green', shadow: 'shadow-glow-green', pulse: true },
  connected: { color: 'bg-green', shadow: 'shadow-glow-green', pulse: true },
  triggered: { color: 'bg-red', shadow: 'shadow-glow-red', pulse: false },
  disconnected: { color: 'bg-red', shadow: 'shadow-glow-red', pulse: false },
  pending: { color: 'bg-amber', shadow: 'shadow-glow-amber', pulse: true },
  rotated: { color: 'bg-amber', shadow: 'shadow-glow-amber', pulse: false },
  expired: { color: 'bg-dim', shadow: '', pulse: false },
};

export function StatusDot({ status, label, showLabel = true }: Props) {
  const cfg = CONFIG[status];
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={`inline-block w-2 h-2 rounded-full ${cfg.color} ${cfg.shadow} ${
          cfg.pulse ? 'animate-pulse-dot' : ''
        }`}
      />
      {showLabel && (
        <span className="text-[11px] uppercase tracking-wider text-secondary">{label ?? status}</span>
      )}
    </span>
  );
}
