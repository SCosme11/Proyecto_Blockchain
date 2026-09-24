# AI Agent Accountability Ledger

A private, per-company blockchain that records **which human took responsibility** for an AI agent's output.

```
Agent output ──hash──► Confidence rules ──► LOW    → sent back to the agent       (off-chain)
                                         ├► HIGH   → auto-accepted               (off-chain)
                                         └► MEDIUM → human review queue
                                                        │  reviewer re-hashes the artifact,
                                                        │  signs in the browser (ECDSA P-256)
                                                        ▼
                                                    Mempool ──► N miners race (PoW) ──► Block ──► Chain
```

* **Backend:** C++17 (OpenSSL 3, libpq, cpp-httplib, nlohmann/json). It does the hashing, signature checks, mining, validation and the REST/SSE API.
* **Frontend:** React + Vite + TypeScript. Reviewers sign with WebCrypto in the browser, so private keys never reach the server.
* **Storage:** PostgreSQL.

## Why there is mining in a private chain

Every node in a company chain has a known identity. So proof-of-work cannot stop fake identities here the way it does in Bitcoin (a Sybil attack is not a threat when every node is known). This project uses **permissioned proof-of-work**:

| | What does it |
|---|---|
| Who may seal blocks | Only registered miners. Each one has its own key pair and signs the blocks it seals. |
| Who seals the next block | The first miner to solve the PoW puzzle. This gives a fair winner with no coordinator. |
| Cost of rewriting history | The PoW has to be redone, **and** each rewritten block needs a registered miner's signature, so any rewrite is traceable to a miner. |
| Rate limiting | The difficulty (number of leading zero bits) controls how fast blocks are made. |

Each miner puts its own name and timestamp in its candidate header, so every miner searches a different part of the hash space. Bitcoin achieves the same with a per-miner coinbase transaction. There is no currency. Miners earn a "blocks sealed" count instead.

For production, the race can be replaced by round-robin Proof-of-Authority without changing the transaction or block formats.

## What the reviewer signs

The reviewer signs this pipe-delimited string (`chain::canonical` in C++, `buildCanonical` in `frontend/src/crypto.ts`):

```
v1|work_item_id|work_hash|artifact_type|score|rules_hash|decision|sha256(comment)|auditor_fingerprint|timestamp_ms
```

* `tx_id = sha256(canonical | signature)`.
* Blocks commit to their transactions through a Bitcoin-style merkle root.
* A block's hash is the double SHA-256 of its header: `v1|height|prev_hash|merkle_root|timestamp_ms|difficulty_bits|miner|nonce`.

`GET /api/chain/verify` checks the whole chain from genesis:

* every block hash, and that each block links to the previous one
* the proof-of-work
* that each miner is registered, and each miner's signature
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
./build/ledger_selftest.exe # checks crypto, merkle, PoW and the rules engine
./build/ledger_server.exe   # creates the DB if missing, applies db/schema.sql, creates genesis

# 4. Frontend (in another terminal)
cd frontend
npm install
npm run dev                 # open http://localhost:5173 (it proxies /api to :8080)
```

* `C:\msys64\ucrt64\bin` must be on your `PATH` when you run the server, because it needs the OpenSSL and libpq DLLs.
* On Linux or macOS, install OpenSSL 3, libpq, CMake and Ninja with your package manager. The rest of the steps are the same.
* **Single-server mode:** run `npm run build`. The C++ node then serves `frontend/dist` itself at `http://127.0.0.1:8080`.

### End-to-end test

With the server running:

```bash
node scripts/e2e.mjs http://127.0.0.1:8080
```

This script **resets the demo data**. It then:

1. Submits LOW, MEDIUM and HIGH work.
2. Signs the MEDIUM item with WebCrypto.
3. Checks that forged and LOW-confidence transactions are rejected.
4. Mines a block with 4 miners.
5. Verifies the chain.
6. Runs each of the 4 tamper attacks and checks that each one is detected.

## Try it out in the UI

1. **Agent work.** Click the preset "Excel forecast emailed to CFO". Because it has external side effects, the rules cap it at MEDIUM.
2. **Review & sign:**
   * Create a reviewer key.
   * Select the item and click **Download & verify SHA-256**.
   * Approve it, then sign.
3. **Mempool.** The transaction shows up here, with its signature re-verified by C++.
4. **Mining arena.** Choose the number of miners and the difficulty, then start a round. The live stream shows each miner's hashrate, and the winner and stale miners are highlighted.
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
backend/src/crypto.*      SHA-256, ECDSA P-256 (raw r||s <-> DER), base64, midstate PoW hasher
backend/src/chain.*       canonical tx format, merkle root, block header hashing, genesis
backend/src/confidence.*  rules engine (LOW / MEDIUM / HIGH)
backend/src/ledger.*      Postgres-backed chain: tip, mempool, block validation, commit, full verify
backend/src/miner.*       N-thread mining race coordinator
backend/src/api.*         REST + Server-Sent Events
db/schema.sql             PostgreSQL schema (applied automatically)
frontend/src/tabs/        Agent simulator, Auditor, Mempool, Mining arena, Chain explorer
scripts/e2e.mjs           end-to-end test
```

## Known limitations (demo scope)

* Miner private keys are stored in Postgres so the demo can create N miners on demand. In production, each miner node keeps its own key, ideally in an HSM.
* All miners are threads inside a single process. There is no P2P networking and no fork resolution beyond "first valid block wins".
* Timestamps come from the reviewer's clock, checked to within ±5 minutes of the node's clock. For legally strong timestamps, add RFC 3161 or anchor the chain periodically to a public chain.
* HIGH-confidence work is auto-accepted and never appears on the chain. If the business needs accountability for it too, commit a periodic merkle root of those decisions to the chain.
