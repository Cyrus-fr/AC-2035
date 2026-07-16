// Shared types mirroring the AC-2035 API responses.

export type NodeType = 'ExternalIP' | 'Pod' | 'Honeytoken' | 'Identity' | 'Technique' | 'Service' | string;
export type EdgeType = 'CONNECTED_TO' | 'MOVED_TO' | 'ACCESSED' | 'TRIGGERED' | string;

export interface CyNode {
  data: {
    id: string;
    label: string;
    type: NodeType;
    properties?: Record<string, unknown>;
    attack_path?: boolean;
  };
}

export interface CyEdge {
  data: {
    id: string;
    source: string;
    target: string;
    type: EdgeType;
    timestamp?: string | null;
    confidence?: string | null;
    cf_ray?: string | null;
    attack_path?: boolean;
  };
}

export interface GraphData {
  nodes: CyNode[];
  edges: CyEdge[];
}

export interface GraphStats {
  node_count: number;
  edge_count: number;
  honeytoken_count: number;
  external_ip_count: number;
  pod_count: number;
}

export type TokenStatus = 'active' | 'triggered' | 'rotated' | 'expired';

export interface Token {
  token_id: string;
  token_type: string;
  target_pod: string | null;
  target_namespace: string | null;
  secret_manager_path: string | null;
  injected_at: string | null;
  last_rotated_at: string | null;
  status: TokenStatus;
}

export type AlertType = 'honeytoken_trigger' | 'killswitch_fired' | 'token_rotated' | 'system_info';

export interface Alert {
  type: AlertType | 'connected' | 'ping';
  token_id?: string | null;
  timestamp?: string;
  data?: Record<string, unknown>;
  message?: string;
}

export interface PathHop {
  from_node: string;
  to_node: string;
  edge_type: string;
  timestamp: string | null;
  confidence: string | null;
  cf_ray: string | null;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  hop_index: number;
}

export interface AttackObject {
  token_id: string;
  entry_point: string | null;
  movement_path: PathHop[];
  dwell_time_seconds: number;
  blast_radius: string[];
  confidence: string;
  mitre_techniques: MitreTechnique[];
  all_paths: unknown[];
  reconstructed_at: string;
}

export interface KillSwitchAction {
  action_type: string;
  target: string;
  success: boolean;
  error: string | null;
  timestamp: string;
  verified?: boolean | null;
  rolled_back?: boolean | null;
}

export interface KillSwitchResult {
  pending_id: string;
  status: 'executed' | 'pending' | 'partial' | 'failed';
  attack_object_token_id: string;
  actions: KillSwitchAction[];
  executed_at: string | null;
  triggered_by: string;
}

export interface PendingItem {
  pending_id: string;
  token_id: string | null;
  entry_point?: string | null;
  confidence?: string | null;
}

// A notifier fallback (.alert) record — written when an external channel fails
// (U0). Surfaced by GET /api/notifications so a dead webhook can't hide alerts.
export interface FallbackAlert {
  kind?: string;
  token_id?: string | null;
  title?: string;
  severity?: string;
  fields?: Record<string, unknown>;
  timestamp?: string;
  fallback?: boolean;
  written_at?: string;
}

export interface TriggerResponse {
  attack_object: AttackObject;
  killswitch_result: KillSwitchResult;
}

// A normalized timeline event (Phase 2), used by the Attack Timeline view.
export interface TimelineEvent {
  event_id: string;
  event_type: 'cloudflare_access' | 'vpc_flow' | 'k8s_log' | string;
  timestamp: string;
  source: string;
  pod_name?: string | null;
  namespace?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  cf_ray?: string | null;
  process_name?: string | null;
  raw?: Record<string, unknown>;
}

export type ViewId = 'graph' | 'alerts' | 'tokens' | 'timeline' | 'killswitch';
