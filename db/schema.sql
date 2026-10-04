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

-- Permissioned nodes (company machines). The same set of nodes acts as miners in PoW mode
-- or as validators in PoS mode -- it is one identity/key-pair registry either way. Private
-- key kept here ONLY for the demo: in production each node holds its own key in an HSM.
CREATE TABLE IF NOT EXISTS nodes (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    public_key_spki TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    stake           BIGINT NOT NULL DEFAULT 0,
    active          BOOLEAN NOT NULL DEFAULT true,
    slashed         BOOLEAN NOT NULL DEFAULT false,
    dishonest       BOOLEAN NOT NULL DEFAULT false,  -- toggled by the demo to force invalid proposals
    blocks_proposed INTEGER NOT NULL DEFAULT 0,
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
    height              BIGINT PRIMARY KEY,
    hash                TEXT NOT NULL UNIQUE,
    prev_hash           TEXT NOT NULL,
    merkle_root         TEXT NOT NULL,
    timestamp_ms        BIGINT NOT NULL,
    mode                TEXT NOT NULL DEFAULT 'pos' CHECK (mode IN ('pow','pos')),
    nonce               BIGINT NOT NULL DEFAULT 0,   -- PoW: winning nonce. PoS: always 0.
    difficulty_hex_zeros INTEGER NOT NULL DEFAULT 0, -- PoW: required leading hex zero digits.
    proposer_name       TEXT NOT NULL,               -- winning miner (PoW) or sorteed validator (PoS)
    proposer_signature  TEXT NOT NULL,              -- proposer's ECDSA signature over the block hash
    quorum_stake        BIGINT NOT NULL,             -- PoS: stake that actually voted. PoW: 0.
    total_stake         BIGINT NOT NULL,             -- PoS: quorum denominator. PoW: 0.
    tx_count            INTEGER NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One signed vote per validator per block (PoS only); the sum of stake_at_vote must reach
-- >= 2/3 of blocks.total_stake for the block to have been committed at all.
CREATE TABLE IF NOT EXISTS block_votes (
    id            SERIAL PRIMARY KEY,
    block_height  BIGINT NOT NULL REFERENCES blocks(height),
    validator_id  INTEGER NOT NULL REFERENCES nodes(id),
    signature     TEXT NOT NULL,
    stake_at_vote BIGINT NOT NULL,
    voted_at_ms   BIGINT NOT NULL,
    UNIQUE (block_height, validator_id)
);

-- PoW reward maturity: the reward for the block at `height` is pending until the chain
-- reaches height+6, at which point it is credited (confirmed) to the miner -- a counter,
-- never a transferable balance.
CREATE TABLE IF NOT EXISTS pow_rewards (
    height       BIGINT PRIMARY KEY REFERENCES blocks(height),
    miner_id     INTEGER NOT NULL REFERENCES nodes(id),
    confirmed    BOOLEAN NOT NULL DEFAULT false,
    confirmed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
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

-- One row per consensus round or PoS proposal attempt (whether or not it produced a block).
-- participants snapshots the stake table used for proposer selection, so verify_chain can
-- re-check history even after later staking/slashing changed the live `nodes` table.
CREATE TABLE IF NOT EXISTS consensus_rounds (
    id            SERIAL PRIMARY KEY,
    mode          TEXT NOT NULL CHECK (mode IN ('pow','pos')),
    attempt       INTEGER NOT NULL DEFAULT 0,       -- PoS: redraw counter ("intento") within the round
    proposer      TEXT,
    participants  JSONB NOT NULL,                 -- [{validator, stake, vote: yes|absent|double_vote}]
    block_height  BIGINT,
    quorum_stake  BIGINT NOT NULL,
    total_stake   BIGINT NOT NULL,
    duration_ms   BIGINT NOT NULL,
    outcome       TEXT NOT NULL CHECK (outcome IN ('sealed','no_quorum','rejected','rejected_retry')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit trail of slashing: a validator caught signing two conflicting blocks (equivocation)
-- or proposing a dishonest/invalid block loses its stake and is barred from future rounds.
CREATE TABLE IF NOT EXISTS slashing_events (
    id            SERIAL PRIMARY KEY,
    validator_id  INTEGER NOT NULL REFERENCES nodes(id),
    reason        TEXT NOT NULL,                   -- double_vote | dishonest_proposal
    evidence      JSONB NOT NULL,
    stake_before  BIGINT NOT NULL,
    stake_after   BIGINT NOT NULL,
    block_height  BIGINT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
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
