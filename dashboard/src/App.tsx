import { useState } from 'react';
import { Sidebar } from './components/Layout/Sidebar';
import { TopBar } from './components/Layout/TopBar';
import { AttackGraph } from './components/Graph/AttackGraph';
import { AlertFeed } from './components/Alerts/AlertFeed';
import { TokenBoard } from './components/Tokens/TokenBoard';
import { AttackTimeline } from './components/Timeline/AttackTimeline';
import { KillSwitchPanel } from './components/KillSwitch/KillSwitchPanel';
import { useWebSocket } from './hooks/useWebSocket';
import type { ViewId } from './types';

export default function App() {
  const [view, setView] = useState<ViewId>('graph');
  const [collapsed, setCollapsed] = useState(false);

  // Explicit ws:// URL from VITE_WS_URL — never derived from window.location
  // or routed through the Vite proxy.
  const ws = useWebSocket(
    (import.meta.env.VITE_WS_URL as string | undefined) ?? 'ws://localhost:8000/ws',
  );

  return (
    <div className="scanlines flex h-screen flex-col bg-base text-primary">
      <TopBar connected={ws.connected} />
      <div className="flex min-h-0 flex-1">
        <Sidebar
          active={view}
          onSelect={setView}
          collapsed={collapsed}
          onToggleCollapse={() => setCollapsed((v) => !v)}
        />
        <main className="relative min-w-0 flex-1 overflow-hidden">
          {view === 'graph' && <AttackGraph />}
          {view === 'alerts' && <AlertFeed messages={ws.messages} connected={ws.connected} />}
          {view === 'tokens' && <TokenBoard />}
          {view === 'timeline' && <AttackTimeline />}
          {view === 'killswitch' && <KillSwitchPanel />}
        </main>
      </div>
    </div>
  );
}
