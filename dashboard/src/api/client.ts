import axios, { AxiosError } from 'axios';
import type {
  AttackObject,
  FallbackAlert,
  GraphData,
  GraphStats,
  KillSwitchResult,
  PendingItem,
  Token,
  TriggerResponse,
} from '../types';

const baseURL = (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:8000';

const http = axios.create({ baseURL, timeout: 30000 });

// 404 → null; anything else → throw with a useful message.
function is404(err: unknown): boolean {
  return err instanceof AxiosError && err.response?.status === 404;
}

function wrap(err: unknown): never {
  if (err instanceof AxiosError) {
    const detail = (err.response?.data as { detail?: string } | undefined)?.detail;
    throw new Error(detail ?? err.message);
  }
  throw err as Error;
}

export const api = {
  async health(): Promise<{ status: string }> {
    const { data } = await http.get('/health');
    return data;
  },

  async getGraph(): Promise<GraphData> {
    try {
      const { data } = await http.get<GraphData>('/api/graph/full');
      return data;
    } catch (err) {
      wrap(err);
    }
  },

  async getAttackPath(tokenId: string): Promise<GraphData | null> {
    try {
      const { data } = await http.get<GraphData>(`/api/graph/attack/${encodeURIComponent(tokenId)}`);
      return data;
    } catch (err) {
      if (is404(err)) return null;
      wrap(err);
    }
  },

  async getStats(): Promise<GraphStats> {
    try {
      const { data } = await http.get<GraphStats>('/api/graph/stats');
      return data;
    } catch (err) {
      wrap(err);
    }
  },

  async clearGraph(): Promise<{ cleared: boolean }> {
    const { data } = await http.post('/api/graph/clear');
    return data;
  },

  async getTokens(status?: string): Promise<Token[]> {
    try {
      const { data } = await http.get<Token[]>('/api/tokens', { params: status ? { status } : undefined });
      return data;
    } catch (err) {
      wrap(err);
    }
  },

  async getToken(tokenId: string): Promise<Token | null> {
    try {
      const { data } = await http.get<Token>(`/api/tokens/${encodeURIComponent(tokenId)}`);
      return data;
    } catch (err) {
      if (is404(err)) return null;
      wrap(err);
    }
  },

  async rotateTokens(): Promise<{ rotated: number }> {
    const { data } = await http.post('/api/tokens/rotate');
    return data;
  },

  async getAlerts(limit = 50): Promise<KillSwitchResult[]> {
    try {
      const { data } = await http.get<KillSwitchResult[]>('/api/alerts', { params: { limit } });
      return data;
    } catch (err) {
      wrap(err);
    }
  },

  async getAlertsForToken(tokenId: string): Promise<KillSwitchResult[] | null> {
    try {
      const { data } = await http.get<KillSwitchResult[]>(`/api/alerts/${encodeURIComponent(tokenId)}`);
      return data;
    } catch (err) {
      if (is404(err)) return null;
      wrap(err);
    }
  },

  async getNotifications(limit = 50): Promise<FallbackAlert[]> {
    try {
      const { data } = await http.get<FallbackAlert[]>('/api/notifications', { params: { limit } });
      return data;
    } catch (err) {
      wrap(err);
    }
  },

  async triggerPipeline(event: Record<string, unknown>): Promise<TriggerResponse> {
    try {
      const { data } = await http.post<TriggerResponse>('/api/alerts/trigger', event);
      return data;
    } catch (err) {
      wrap(err);
    }
  },

  async getPending(): Promise<PendingItem[]> {
    try {
      const { data } = await http.get<PendingItem[]>('/api/killswitch/pending');
      return data;
    } catch (err) {
      wrap(err);
    }
  },

  async approve(pendingId: string): Promise<KillSwitchResult | null> {
    try {
      const { data } = await http.post<KillSwitchResult>(
        `/api/killswitch/approve/${encodeURIComponent(pendingId)}`,
      );
      return data;
    } catch (err) {
      if (is404(err)) return null;
      wrap(err);
    }
  },

  async executeKillSwitch(attackObject: AttackObject): Promise<KillSwitchResult> {
    try {
      const { data } = await http.post<KillSwitchResult>('/api/killswitch/execute', attackObject);
      return data;
    } catch (err) {
      wrap(err);
    }
  },
};

export type Api = typeof api;
