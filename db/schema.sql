-- AI Agent Accountability Ledger — PostgreSQL schema.
-- Idempotent: the C++ server applies it on startup (SCHEMA_PATH), or run manually:
--   psql -h localhost -U postgres -d ai_ledger -f db/schema.sql

-- Human reviewers. Only the PUBLIC key is stored; private keys never leave the browser.
CREATE TABLE IF NOT EXISTS auditors (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    public_key_spki TEXT NOT NULL UNIQUE,          -- base64 DER SubjectPublicKeyInfo (P-256)
    fingerprint     TEXT NOT NULL UNIQUE,          -- sha256(DER) hex, the on-chain identity
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Permissioned miners (company nodes). Private key kept here ONLY for the demo:
-- in production each node holds its own key in an HSM / keystore.
CREATE TABLE IF NOT EXISTS miners (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    public_key_spki TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    blocks_mined    INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every piece of agent output, whatever its confidence. Only MEDIUM items can become transactions.
CREATE TABLE IF NOT EXISTS work_items (
    id            BIGSERIAL PRIMARY KEY,
    agent_name    TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    filename      TEXT NOT NULL,
    content       BYTEA NOT NULL,                  -- off-chain artifact; its hash goes on-chain
    size_bytes    INTEGER NOT NULL,
    work_hash     TEXT NOT NULL,
    metrics       JSONB NOT NULL,
    score         NUMERIC(6,4) NOT NULL,
    category      TEXT NOT NULL CHECK (category IN ('LOW','MEDIUM','HIGH')),
    reasons       JSONB NOT NULL,
    rules_version TEXT NOT NULL,
    rules_hash    TEXT NOT NULL,
    status        TEXT NOT NULL,                   -- rework_required | auto_accepted | pending_review | signed | on_chain
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS work_items_category_status ON work_items (category, status);

CREATE TABLE IF NOT EXISTS blocks (
    height          BIGINT PRIMARY KEY,
    hash            TEXT NOT NULL UNIQUE,
    prev_hash       TEXT NOT NULL,
    merkle_root     TEXT NOT NULL,
    timestamp_ms    BIGINT NOT NULL,
    difficulty_bits INTEGER NOT NULL,
    nonce           BIGINT NOT NULL,
    miner_name      TEXT NOT NULL,
    miner_signature TEXT NOT NULL,                 -- miner's ECDSA signature over the block hash
    tx_count        INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Signed human approvals. status: mempool -> confirmed (once mined into a block).
CREATE TABLE IF NOT EXISTS transactions (
    tx_id        TEXT PRIMARY KEY,                 -- sha256(canonical | signature)
    work_item_id BIGINT NOT NULL UNIQUE REFERENCES work_items(id),
    auditor_id   INTEGER NOT NULL REFERENCES auditors(id),
    canonical    TEXT NOT NULL,                    -- the exact bytes the auditor signed
    signature    TEXT NOT NULL,                    -- raw r||s hex (WebCrypto format)
    decision     TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
    comment      TEXT NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'mempool',
    block_height BIGINT REFERENCES blocks(height),
    block_index  INTEGER,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS transactions_status ON transactions (status);

CREATE TABLE IF NOT EXISTS mining_rounds (
    id              SERIAL PRIMARY KEY,
    difficulty_bits INTEGER NOT NULL,
    participants    JSONB NOT NULL,                -- per-miner hashes / status
    winner          TEXT,
    block_height    BIGINT,
    duration_ms     BIGINT NOT NULL,
    hashes_total    BIGINT NOT NULL,
    outcome         TEXT NOT NULL,                 -- sealed | stopped | rejected
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Records edits made by the "tamper demo" so they can be reverted.
CREATE TABLE IF NOT EXISTS tamper_log (
    id             SERIAL PRIMARY KEY,
    kind           TEXT NOT NULL,
    target         TEXT NOT NULL,
    original_text  TEXT,
    original_bytes BYTEA,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
