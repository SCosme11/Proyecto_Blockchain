// Typed client for the C++ node's REST API.

export type Category = 'LOW' | 'MEDIUM' | 'HIGH';
export type Decision = 'APPROVED' | 'REJECTED';

export interface Config {
  rules_version: string;
  rules_hash: string;
  rules: {
    artifact_type_risk: Record<string, number>;
    thresholds: { high: number; low: number };
    weights: Record<string, number>;
    [k: string]: unknown;
  };
  tx_version: string;
  initial_stake: number;
  max_tx_per_block: number;
  min_nodes: number;
  max_nodes: number;
  min_difficulty_hex_zeros: number;
  max_difficulty_hex_zeros: number;
  quorum_numerator: number;
  quorum_denominator: number;
  timestamp_skew_ms: number;
}

export interface Stats {
  work_total: number;
  low: number;
  medium: number;
  high: number;
  pending_review: number;
  mempool: number;
  confirmed: number;
  height: number;
  auditors: number;
  nodes: number;
  total_stake: number;
  consensus_running: boolean;
  consensus_mode: 'pow' | 'pos' | '';
}

export interface Metrics {
  self_confidence: number;
  tests_passed_ratio: number;
  lines_changed: number;
  has_external_side_effects: boolean;
}

export interface WorkItem {
  id: number;
  agent_name: string;
  artifact_type: string;
  filename: string;
  size_bytes: number;
  work_hash: string;
  metrics: Metrics;
  score: string;
  category: Category;
  reasons: string[];
  rules_version: string;
  rules_hash: string;
  status: string;
  created_at: string;
  tx_id: string | null;
  decision: Decision | null;
  block_height: number | null;
  auditor_name: string | null;
  breakdown?: Record<string, { signal: number; weight: number }>;
}

export interface Tx {
  tx_id: string;
  work_item_id: number;
  canonical: string;
  signature: string;
  decision: Decision;
  comment: string;
  timestamp_ms: number;
  status: 'mempool' | 'confirmed';
  block_height: number | null;
  auditor: { id: number; name: string; fingerprint: string };
  work: { agent_name: string; artifact_type: string; filename: string; work_hash: string; score: string };
  signature_valid?: boolean;
  tx_id_valid?: boolean;
}

export interface Vote {
  validator: string;
  signature: string;
  stake: number;
}

export interface Block {
  height: number;
  hash: string;
  prev_hash: string;
  merkle_root: string;
  timestamp_ms: number;
  mode: 'pow' | 'pos';
  nonce: number;
  difficulty_hex_zeros: number;
  proposer: string;
  proposer_signature: string;
  quorum_stake: number;
  total_stake: number;
  tx_count: number;
  header_preimage: string;
  votes?: Vote[];
  transactions?: Tx[];
}

export interface NodeInfo {
  id: number;
  name: string;
  fingerprint: string;
  stake: number;
  active: boolean;
  slashed: boolean;
  dishonest: boolean;
  blocks_proposed: number;
}

export interface NodeSyncStatus {
  node_id: number;
  name: string;
  height: number;
  hash: string;
  synced: boolean;
  note: string | null;
}

export interface Reward {
  height: number;
  miner: string;
  confirmed: boolean;
}

export interface LogEvent {
  type: 'block' | 'round_rejected' | 'slash' | 'reward_confirmed';
  message: string;
  created_at: string;
}

export interface MinerLive {
  name: string;
  nonce: number;
  attempts: number;
  last_hash: string | null;
  status: 'idle' | 'mining' | 'winner' | 'late' | 'stale';
}

export interface ValidatorLive {
  name: string;
  stake: number;
  dishonest: boolean;
  status: 'idle' | 'voting' | 'voted' | 'abstained';
  signature: string | null;
}

export interface ConsensusResult {
  outcome: 'sealed' | 'no_quorum' | 'rejected' | 'error';
  proposer?: string;
  height?: number;
  hash?: string;
  nonce?: number;
  quorum_stake?: number;
  total_stake?: number;
  tx_count?: number;
  attempts?: number;
  error?: string;
}

export interface AttemptLogEntry {
  attempt: number;
  proposer: string;
  dishonest: boolean;
  quorum_stake: number;
  total_stake: number;
  outcome: 'sealed' | 'rejected' | 'rejected_retry' | 'no_quorum';
}

export interface ConsensusSnapshot {
  round: number;
  running: boolean;
  mode: 'pow' | 'pos' | '';
  height: number;
  prev_hash: string;
  tx_ids: string[];
  elapsed_ms: number;
  result: ConsensusResult | null;
  // mode === 'pow'
  miners?: MinerLive[];
  // mode === 'pos'
  proposer?: string;
  attempt?: number;
  total_stake?: number;
  quorum_threshold?: number;
  quorum_stake?: number;
  attempts_log?: AttemptLogEntry[];
  validators?: ValidatorLive[];
}

export interface Round {
  id: number;
  mode: 'pow' | 'pos';
  attempt: number;
  proposer: string | null;
  participants: { validator: string; stake: number; vote: string }[];
  block_height: number | null;
  quorum_stake: number;
  total_stake: number;
  duration_ms: number;
  outcome: string;
}

export interface ChainVerification {
  ok: boolean;
  height: number;
  first_bad_height: number | null;
  blocks: { height: number; hash: string; ok: boolean; errors: string[] }[];
}

export class ApiError extends Error {
  constructor(message: string, public status: number, public details?: unknown) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error page */
  }
  if (!res.ok) throw new ApiError(data?.error ?? `HTTP ${res.status}`, res.status, data?.details);
  return data as T;
}

export const api = {
  config: () => request<Config>('GET', '/api/config'),
  stats: () => request<Stats>('GET', '/api/stats'),

  submitWork: (body: {
    agent_name: string;
    artifact_type: string;
    filename: string;
    content_b64?: string;
    content_text?: string;
    metrics: Metrics;
  }) => request<WorkItem>('POST', '/api/work', body),
  work: (category?: Category) => request<WorkItem[]>('GET', `/api/work${category ? `?category=${category}` : ''}`),
  workContent: (id: number) =>
    request<{ filename: string; work_hash: string; content_b64: string }>('GET', `/api/work/${id}/content`),
  reviewQueue: () => request<WorkItem[]>('GET', '/api/review-queue'),

  registerAuditor: (name: string, public_key_spki: string) =>
    request<{ id: number; name: string; fingerprint: string }>('POST', '/api/auditors', { name, public_key_spki }),

  submitTx: (body: {
    work_item_id: number;
    auditor_id: number;
    decision: Decision;
    comment: string;
    timestamp_ms: number;
    signature: string;
    canonical: string;
  }) => request<Tx>('POST', '/api/transactions', body),
  mempool: () => request<Tx[]>('GET', '/api/mempool'),

  nodes: () => request<NodeInfo[]>('GET', '/api/nodes'),
  provisionNodes: (count: number, stake: number) => request<NodeInfo[]>('POST', '/api/nodes', { count, stake }),
  adjustStake: (id: number, delta: number) => request<NodeInfo[]>('POST', `/api/nodes/${id}/stake`, { delta }),
  setDishonest: (id: number, dishonest: boolean) =>
    request<NodeInfo[]>('POST', `/api/nodes/${id}/dishonest`, { dishonest }),
  nodesSync: () => request<NodeSyncStatus[]>('GET', '/api/nodes/sync'),
  resyncNode: (id: number) => request<NodeSyncStatus[]>('POST', `/api/nodes/${id}/resync`),
  rewards: () => request<Reward[]>('GET', '/api/rewards'),
  events: () => request<LogEvent[]>('GET', '/api/events'),

  propose: (
    mode: 'pow' | 'pos',
    nodes: number,
    difficulty_hex_zeros: number,
    abstain: number,
    punishment_rule: 'A' | 'B' = 'A',
    alpha = 1,
  ) =>
    request<ConsensusSnapshot>('POST', '/api/consensus/propose', {
      mode,
      nodes,
      difficulty_hex_zeros,
      abstain,
      punishment_rule,
      alpha,
    }),
  stopConsensus: () => request<unknown>('POST', '/api/consensus/stop'),
  consensusStatus: () => request<ConsensusSnapshot>('GET', '/api/consensus/status'),
  rounds: () => request<Round[]>('GET', '/api/rounds'),

  blocks: () => request<Block[]>('GET', '/api/blocks'),
  block: (h: number) => request<Block>('GET', `/api/blocks/${h}`),
  verify: () => request<ChainVerification>('GET', '/api/chain/verify'),

  tamper: (
    kind: 'tx_decision' | 'comment' | 'artifact' | 'validator_signature' | 'node_copy' | 'reward_amount',
  ) => request<{ kind: string; target: string; change: string }>('POST', '/api/demo/tamper', { kind }),
  restore: () => request<{ restored: number }>('POST', '/api/demo/restore'),
  reset: () => request<unknown>('POST', '/api/demo/reset'),
};
