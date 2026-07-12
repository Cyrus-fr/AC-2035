import { useEffect, useRef, useState, useCallback } from 'react';
import type { Alert } from '../types';

const MAX_MESSAGES = 200;
const BASE_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;

interface UseWebSocketResult {
  connected: boolean;
  lastMessage: Alert | null;
  messages: Alert[];
}

/**
 * Connects to the given explicit ws:// URL (passed in from VITE_WS_URL — never
 * derived from window.location or the Vite proxy). Auto-reconnects with
 * exponential backoff (1s → 2s → … capped at 30s). Keeps the last 200
 * messages. On reconnect, injects a system_info "WebSocket reconnected" alert.
 */
export function useWebSocket(url: string): UseWebSocketResult {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<Alert[]>([]);
  const [lastMessage, setLastMessage] = useState<Alert | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const backoffRef = useRef(BASE_BACKOFF_MS);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hasConnectedOnce = useRef(false);
  const closedByUs = useRef(false);

  const pushMessage = useCallback((msg: Alert) => {
    setMessages((prev) => {
      const next = [msg, ...prev];
      return next.length > MAX_MESSAGES ? next.slice(0, MAX_MESSAGES) : next;
    });
    setLastMessage(msg);
  }, []);

  const connect = useCallback(() => {
    if (!url) return;
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch {
      // Schedule a retry if construction itself throws.
      scheduleReconnect();
      return;
    }
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      backoffRef.current = BASE_BACKOFF_MS;
      if (hasConnectedOnce.current) {
        pushMessage({
          type: 'system_info',
          timestamp: new Date().toISOString(),
          data: { message: 'WebSocket reconnected' },
        });
      }
      hasConnectedOnce.current = true;
    };

    ws.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data as string) as Alert;
        // Pings are keepalives, not feed events.
        if (parsed.type === 'ping') return;
        pushMessage(parsed);
      } catch {
        /* ignore malformed frames */
      }
    };

    ws.onclose = () => {
      setConnected(false);
      if (!closedByUs.current) scheduleReconnect();
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [url, pushMessage]);

  const scheduleReconnect = useCallback(() => {
    if (reconnectTimer.current) return;
    const delay = backoffRef.current;
    reconnectTimer.current = setTimeout(() => {
      reconnectTimer.current = null;
      backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS);
      connect();
    }, delay);
  }, [connect]);

  useEffect(() => {
    closedByUs.current = false;
    connect();
    return () => {
      closedByUs.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url]);

  return { connected, lastMessage, messages };
}
