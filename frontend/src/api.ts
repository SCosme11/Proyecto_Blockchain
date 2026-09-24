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
  default_difficulty: number;
  max_tx_per_block: number;
  max_miners: number;
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
  miners: number;
  mining: boolean;
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

export interface Block {
  height: number;
  hash: string;
  prev_hash: string;
  merkle_root: string;
  timestamp_ms: number;
  difficulty_bits: number;
  nonce: number;
  miner: string;
  miner_signature: string;
  tx_count: number;
  header_preimage: string;
  transactions?: Tx[];
}

export interface MinerInfo {
  id: number;
  name: string;
  fingerprint: string;
  blocks_mined: number;
}

export interface MinerLive {
  name: string;
  hashes: number;
  hashrate: number;
  status: 'idle' | 'mining' | 'winner' | 'late' | 'stale';
  nonce: number | null;
  hash: string | null;
}

export interface MiningSnapshot {
  round: number;
  running: boolean;
  difficulty_bits: number;
  expected_hashes: number;
  height: number;
  prev_hash: string;
  tx_ids: string[];
  elapsed_ms: number;
  total_hashes: number;
  total_hashrate: number;
  miners: MinerLive[];
  result: null | {
    outcome: 'sealed' | 'stopped' | 'rejected' | 'error';
    winner?: string;
    height?: number;
    hash?: string;
    nonce?: number;
    tx_count?: number;
    error?: string;
  };
}

export interface Round {
  id: number;
  difficulty_bits: number;
  participants: { miner: string; hashes: number; status: string }[];
  winner: string | null;
  block_height: number | null;
  duration_ms: number;
  hashes_total: number;
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

  miners: () => request<MinerInfo[]>('GET', '/api/miners'),
  mine: (miners: number, difficulty_bits: number) =>
    request<MiningSnapshot>('POST', '/api/mine', { miners, difficulty_bits }),
  stopMining: () => request<unknown>('POST', '/api/mine/stop'),
  rounds: () => request<Round[]>('GET', '/api/rounds'),

  blocks: () => request<Block[]>('GET', '/api/blocks'),
  block: (h: number) => request<Block>('GET', `/api/blocks/${h}`),
  verify: () => request<ChainVerification>('GET', '/api/chain/verify'),

  tamper: (kind: 'tx_decision' | 'comment' | 'artifact' | 'block_nonce') =>
    request<{ kind: string; target: string; change: string }>('POST', '/api/demo/tamper', { kind }),
  restore: () => request<{ restored: number }>('POST', '/api/demo/restore'),
  reset: () => request<unknown>('POST', '/api/demo/reset'),
};
