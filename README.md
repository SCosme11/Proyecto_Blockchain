# AI Agent Accountability Ledger

A private, per-company blockchain that records **which human took responsibility** for an AI agent's output.

```
Agent output ──hash──► Confidence rules ──► LOW    → sent back to the agent       (off-chain)
                                         ├► HIGH   → auto-accepted               (off-chain)
                                         └► MEDIUM → human review queue
                                                        │  reviewer re-hashes the artifact,
                                                        │  signs in the browser (ECDSA P-256)
                                                        ▼
                                                    Mempool ──► PoW or PoS (chosen per round) ──► Block ──► Chain
                                                                   │
                                                                   └─► broadcast to every node's own chain copy
```

* **Backend:** C++17 (OpenSSL 3, libpq, cpp-httplib, nlohmann/json). It does the hashing, signature checks, both consensus modes, validation and the REST/SSE API.
* **Frontend:** React + Vite + TypeScript. Reviewers sign with WebCrypto in the browser, so private keys never reach the server.
* **Storage:** PostgreSQL (the reference/durable chain); each simulated node additionally keeps its own in-memory chain mirror, updated by broadcast like the assignment guide asks for.

This project follows `guia_simulador_blockchain.pdf` (Universidad Anáhuac México, examen de MT): a simulator with **both** a Proof-of-Work and a Proof-of-Stake mode, 10–20 nodes, signed transactions, and a long list of edge cases it must survive without crashing. The guide suggests Python + Flask; this project implements the same specification on the existing C++/PostgreSQL/React stack instead. The 4-page academic report justifying the math behind every design choice is in [`report/reporte.tex`](report/reporte.tex).

## Two consensus modes, one block/transaction format

Both modes share `chain::BlockHeader`, the canonical transaction format, and the per-node broadcast/validation rule; only the "who gets to seal the next block" rule differs.

| | V1 · Proof of Work | V2 · Proof of Stake |
|---|---|---|
| Who may seal blocks | Any registered node, as a miner. | Only the node a stake-weighted lottery ("sorteo") selects. |
| Who wins | The first miner to find a nonce whose block hash has `d` leading **hex** zero digits. Miner `i` of `N` only tries nonces `i, i+N, i+2N, …` — disjoint by construction, so a tie is settled by **smallest winning nonce** (never a real collision). | A proposer drawn with probability proportional to its stake. The block seals once validators holding **≥ 2/3 of the active stake** sign it (the classic BFT bound, tolerating < 1/3 faulty/offline stake). |
| Bets | N/A | Every validator bets `0 < a_i ≤ its stake` (default: `bet_pct`% of it, or an explicit `bets: {node: amount}`); the bet is **locked** for the round and released when it ends. The lottery and the votes are weighted by the bet. `validators: k` restricts the round to a seeded random subset of k nodes. |
| Misbehavior | N/A (any registered key can mine). | A node flagged **dishonest** proposes a block with a corrupted signature; honest validators vote **no**, it is **slashed** following a configurable rule (`punishment_rule` on `POST /api/consensus/propose`): **A** `c = a_p` (loses its whole bet and is barred from future rounds), **B** `c = min(a_p, ceil(alpha · tx_count · TX_VALUE))` (0 < alpha ≤ 1; keeps the node eligible) — and the sorteo repeats with an incremented "intento" over the remaining pool either way. |
| Reward | Pending until the chain reaches `height + 6` ("6 confirmations"); only then `BLOCK_REWARD` is credited to the miner's **balance** (available). `POST /api/rewards/:h/claim` before that answers 409 with the missing confirmations. | `POS_REWARD` is credited to the proposer's balance as soon as the block is accepted. |
| State machine | `MINANDO → GANADOR` | `APUESTAS → SORTEO → CANDIDATO → VOTACION → ACEPTADO / RECHAZADO` (shown live in the UI and returned as `phase` / `phase_log`). |

The assignment's "transactions between accounts" are replaced by this system's real transactions (signed reviewer approvals), so there is no transferable money and no double spend in the guide's sense (see `report/reporte.tex` §5). The guide's balance-related cases map to the node's **stake** (apuesta mayor al saldo, cero o negativa → rejected) and to the **one-signature-per-work-item** rule (double submission → 409). *Balance* (rewards) and *stake* (what can be bet) are separate counters.

**Reproducible randomness:** the lottery itself is deterministic from chain data (`prev_hash|height|attempt`). Everything else that is random (which nodes form the validator subset, vote delays) derives from a `seed` (`SEED` in `.env` or `{"seed": N}` per round) — same seed, same behaviour.

**External votes:** `POST /api/consensus/vote {validator, vote}` during `VOTACION` (use `vote_window_ms` to keep it open). Only validators simulated as non-responsive (`abstain`) can still vote; a vote from a non-validator is **403**, a second vote from the same validator (or from one that already votes by itself) is **409**, and both are written to the log.

## Node range and chain copies

* `10 ≤ N ≤ 20` nodes, enforced server-side (`POST /api/nodes`, `POST /api/consensus/propose`) regardless of what the UI already restricts to.
* Every node keeps its **own full copy** of the chain in memory (`backend/src/network.*`: blocks, transactions, votes, stake snapshots). After a block is sealed it is broadcast to every node; each one re-runs the **full** block check (`Ledger::check_block`) against its own tip and refuses the block if its own copy is invalid.
* **Longest valid chain rule (guide §2.4):** a chain received from a peer (`POST /api/nodes/:id/receive-chain {kind: valid|shorter|tampered}`, or `/resync`) is adopted only if **every** block validates from genesis **and** it is longer than the node's own chain (a node whose own copy is invalid accepts any valid chain at least as long). Otherwise it is rejected with the reason and the node keeps its chain.
* The tamper demo corrupts a block **in the middle** of a node's own copy (`node_copy`) or of the reference chain (`intermediate_block`, `block_hash`); the whole chain is then rejected from that block on.
* `GET /api/events` merges sealed/rejected rounds, slashing events and matured rewards into one chronological "bitácora", shown in the Consensus arena.

## What the reviewer signs

The reviewer signs this pipe-delimited string (`chain::canonical` in C++, `buildCanonical` in `frontend/src/crypto.ts`):

```
v1|work_item_id|work_hash|artifact_type|score|rules_hash|decision|sha256(comment)|auditor_fingerprint|timestamp_ms
```

* `tx_id = sha256(canonical | signature)`.
* Blocks commit to their transactions through a Bitcoin-style merkle root (an enhancement over the guide's plain field list), and must contain **at least one transaction** — an empty mempool is rejected before a round even starts, with a clear message.
* A block's hash is the double SHA-256 of its header: `v1|height|prev_hash|merkle_root|timestamp_ms|proposer|nonce|difficulty_hex_zeros` (`nonce`/`difficulty_hex_zeros` are 0 for PoS blocks).

`GET /api/chain/verify` checks the whole chain from genesis:

* every block hash, and that each block links to the previous one
* PoW blocks: the hash meets the stored hex-zero-digit difficulty
* PoS blocks: that the proposer was the legitimate stake-weighted selection for that height (replaying the sorteo over the stake snapshot frozen at round time), that the recorded votes reach the ≥ 2/3 stake quorum, and that each vote's signature is valid
* PoS vote set: every voter belongs to that round's stake snapshot, votes at most once, with exactly the snapshot's stake, and `total_stake` equals the snapshot's sum
* PoW difficulty is at least 1 hex zero
* the proposer's own signature over the block hash
* the merkle roots and the tx_ids
* each auditor's signature and fingerprint
* the comment hashes
* that each off-chain artifact still hashes to the `work_hash` that was signed

## Setup (Windows / MSYS2 UCRT64)

```bash
# 1. Toolchain and libraries
pacman -S --needed mingw-w64-ucrt-x86_64-{gcc,cmake,ninja,openssl,postgresql}

# 2. Configuration
cp .env.example .env        # then edit PGUSER / PGPASSWORD / PGDATABASE ...

# 3. Backend
cd backend
cmake -G Ninja -B build
cmake --build build
./build/ledger_selftest.exe # checks crypto, merkle, proposer selection, quorum math and the rules engine
./build/ledger_server.exe   # creates the DB if missing, applies db/schema.sql, creates genesis

# 4. Frontend (in another terminal)
cd frontend
npm install
npm run dev                 # open http://localhost:5173 (it proxies /api to :8080)
```

* `C:\msys64\ucrt64\bin` must be on your `PATH` when you run the server, because it needs the OpenSSL and libpq DLLs.
* On Linux or macOS, install OpenSSL 3, libpq, CMake and Ninja with your package manager. The rest of the steps are the same.
* **Single-server mode:** run `npm run build`. The C++ node then serves `frontend/dist` itself at `http://127.0.0.1:8080`.
* **Upgrading:** the new columns (`nodes.balance`, `nodes.locked`, `pow_rewards.amount`) and the `event_log` table are added
  idempotently on startup (`ALTER TABLE … ADD COLUMN IF NOT EXISTS`). Only a database from before PoS (old `miners`/`mining_rounds`
  tables) still needs `DROP DATABASE ai_ledger;`.
* **Linux / macOS (clean machine):** install OpenSSL 3, libpq, CMake, Ninja and Node; start PostgreSQL (or `docker compose up -d`, which
  provides one on :5432 with the credentials in `.env.example`); then `cp .env.example .env`, build and run as above.

### Tests

With the server running:

```bash
node scripts/e2e.mjs http://127.0.0.1:8080   # happy-path smoke test
node scripts/casos.mjs http://127.0.0.1:8080 # section-5 robustness cases from the guide
```

Run them against a throw-away database so your demo data is untouched:
`PGDATABASE=ai_ledger_test SERVER_PORT=8081 PHASE_DELAY_MS=30 ./build/ledger_server` and point the scripts at `:8081`.

Both scripts **reset the demo data**. `e2e.mjs`: submits LOW/MEDIUM/HIGH work, signs the MEDIUM item with WebCrypto, checks
forged/LOW-confidence transactions are rejected, seals a PoS block with 10 nodes, runs a second round with a dishonest
proposer (checks it still seals and the proposer gets slashed), corrupts and restores one node's local chain copy, then
verifies the chain and runs each tamper attack. `casos.mjs` drives the edge cases in section 5 of the guide:
malformed/mistyped requests (never a 500), N and difficulty out of range, empty mempool, forged/foreign/duplicated signatures and
concurrent double submission, intermediate-block tampering, shorter/invalid chains received by a node, bets above/zero/negative,
locked stake, vote of a non-validator and double votes, quorum exactly at and one vote below 2/3, dishonest proposers under both
punishment rules, all validators slashed, PoW cancellation, 10 PoW blocks in a row, reward claimed before 6 confirmations, a seeded
reproducible validator subset, two tabs starting a round at once and resetting mid-round. `backend/build/ledger_selftest.exe` covers the pure math (nonce-partition
uniqueness, the quorum-threshold lemma, redraw termination) without needing Postgres at all.

## Try it out in the UI

1. **Agent work.** Click the preset "Excel forecast emailed to CFO". Because it has external side effects, the rules cap it at MEDIUM.
2. **Review & sign:**
   * Create a reviewer key.
   * Select the item and click **Download & verify SHA-256**.
   * Approve it, then sign.
3. **Mempool.** The transaction shows up here, with its signature re-verified by C++.
4. **Consensus arena.** Pick **V1 · Proof of Work** or **V2 · Proof of Stake**, choose the node count (10–20) and the
   mode-specific parameter (hex-zero difficulty, or how many validators to simulate as non-responsive), then start a round.
   * PoW: watch each miner's nonce/attempts/last hash live; the winner seals the block.
   * PoS: watch the sorteo pick a proposer and validators vote; mark a node **dishonest** in the "Nodes & stake" table first to
     see it get rejected, slashed, and the sorteo redraw with the rest.
   * The "Nodes (copias de la cadena)" panel shows every node's height/hash and sync status; the "Recompensas PoW" panel
     shows pending vs. confirmed rewards.
5. **Chain:**
   * Click **Verify chain**.
   * Use a tamper button, then click **Verify chain** again to see which block breaks and why.
   * Click **Undo all tampering** to restore everything.

## Confidence rules

`backend/rules/confidence_rules.json` is example policy: weights, thresholds and overrides. Edit it to match your company's real criteria.

* The rules are loaded when the server starts. Restart the server after editing the file.
* The SHA-256 of the rule file is stored with every classification and signed into every transaction. This lets you always prove which policy sent a piece of work to a human.

## Project layout

```
backend/src/crypto.*      SHA-256, ECDSA P-256 (raw r||s <-> DER), base64
backend/src/chain.*       canonical tx format, merkle root, block header hashing, genesis, sorteo, quorum math
backend/src/confidence.*  rules engine (LOW / MEDIUM / HIGH)
backend/src/ledger.*      Postgres-backed chain: tip, mempool, node/stake state, block validation, commit, reward maturity, full verify
backend/src/consensus.*   PoW mining coordinator + PoS sorteo/vote/slash/redraw coordinator (one round at a time, either mode)
backend/src/network.*     per-node in-memory chain mirrors: broadcast, independent validation, tamper/resync
backend/src/api.*         REST + Server-Sent Events
db/schema.sql             PostgreSQL schema (applied automatically)
frontend/src/tabs/        Agent simulator, Auditor, Mempool, Consensus arena (PoW+PoS), Chain explorer
scripts/e2e.mjs           happy-path end-to-end test
scripts/casos.mjs         section-5 robustness/edge-case coverage
report/reporte.tex        4-page academic report: math behind every design decision
```

## Known limitations (demo scope)

* Node private keys are stored in Postgres so the demo can create N nodes on demand. In production, each node keeps its own key, ideally in an HSM.
* All nodes are threads inside a single process; PoW hashing and PoS votes are real, and each node holds its own full chain copy, but there is no real network — "broadcast" is an in-process function call and nodes never fork (one reference ledger decides the next block).
* No transfers or double-spend: stake, balance and rewards are internal counters by design (see `report/reporte.tex`), not a currency.
* The HTTP API has no authentication (demo scope): anyone who can reach it can register auditors or call the `/api/demo/*` helpers.
* Timestamps come from the reviewer's clock, checked to within ±5 minutes of the node's clock. For legally strong timestamps, add RFC 3161 or anchor the chain periodically to a public chain.
* HIGH-confidence work is auto-accepted and never appears on the chain. If the business needs accountability for it too, commit a periodic merkle root of those decisions to the chain.
