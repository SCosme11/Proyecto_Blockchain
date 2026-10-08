#include "ledger.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

#include "crypto.h"

using nlohmann::json;

BlockRow block_from_result(const Result& r, int row) {
    BlockRow b;
    b.header.height = r.i64(row, "height");
    b.header.prev_hash = r.str(row, "prev_hash");
    b.header.merkle_root = r.str(row, "merkle_root");
    b.header.timestamp_ms = r.i64(row, "timestamp_ms");
    b.header.proposer = r.str(row, "proposer_name");
    b.header.nonce = static_cast<uint64_t>(r.i64(row, "nonce"));
    b.header.difficulty_hex_zeros = static_cast<int>(r.i64(row, "difficulty_hex_zeros"));
    b.hash = r.str(row, "hash");
    b.mode = r.str(row, "mode");
    b.proposer_signature = r.str(row, "proposer_signature");
    b.quorum_stake = r.i64(row, "quorum_stake");
    b.total_stake = r.i64(row, "total_stake");
    b.tx_count = static_cast<int>(r.i64(row, "tx_count"));
    return b;
}

void Ledger::apply_schema(const std::string& path) {
    // The schema only ever ADDs (CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS), so a
    // database created by the pre-PoS version keeps its old `blocks` table and every later read
    // would fail with a cryptic "no such column". Detect that up front and say what to do.
    if (db_.exec("SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND "
                 "table_name = 'blocks'").rows() > 0 &&
        db_.exec("SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND "
                 "table_name = 'blocks' AND column_name = 'proposer_name'").rows() == 0) {
        throw DbError(
            "la base de datos tiene el esquema ANTERIOR a PoS/PoW (la tabla `blocks` no tiene `proposer_name`) y no se "
            "puede migrar: su cadena usa otro formato de hash. Usa otra base (cambia PGDATABASE en .env) o recréala: "
            "`ALTER DATABASE <nombre> RENAME TO <nombre>_legacy;` (conserva los datos) o `DROP DATABASE <nombre>;`");
    }
    std::ifstream in(path);
    if (!in) throw DbError("cannot open schema file: " + path);
    std::stringstream ss;
    ss << in.rdbuf();
    db_.exec_script(ss.str());
}

void Ledger::ensure_genesis() {
    auto l = db_.lock();
    if (db_.exec("SELECT 1 FROM blocks WHERE height = 0").rows() > 0) return;
    chain::BlockHeader g = chain::genesis_header();
    db_.exec(
        "INSERT INTO blocks (height, hash, prev_hash, merkle_root, timestamp_ms, mode, nonce, "
        "difficulty_hex_zeros, proposer_name, proposer_signature, quorum_stake, total_stake, tx_count) "
        "VALUES (0,$1,$2,$3,$4,'pos',0,0,$5,'',0,0,0)",
        {chain::block_hash(g), g.prev_hash, g.merkle_root, g.timestamp_ms, g.proposer});
}

BlockRow Ledger::tip() {
    Result r = db_.exec("SELECT * FROM blocks ORDER BY height DESC LIMIT 1");
    if (r.rows() == 0) throw DbError("chain has no genesis block");
    return block_from_result(r, 0);
}

static const char* kTxSelect =
    "SELECT t.tx_id, t.canonical, t.signature, t.comment, t.work_item_id, a.public_key_spki, a.name "
    "FROM transactions t JOIN auditors a ON a.id = t.auditor_id ";

static TxRow tx_from_result(const Result& r, int i) {
    TxRow t;
    t.tx_id = r.str(i, "tx_id");
    t.canonical = r.str(i, "canonical");
    t.signature = r.str(i, "signature");
    t.comment = r.str(i, "comment");
    t.work_item_id = r.i64(i, "work_item_id");
    t.auditor_spki = r.str(i, "public_key_spki");
    t.auditor_name = r.str(i, "name");
    return t;
}

std::vector<TxRow> Ledger::mempool(int limit) {
    Result r = db_.exec(std::string(kTxSelect) +
                            "WHERE t.status = 'mempool' ORDER BY t.timestamp_ms, t.tx_id LIMIT $1",
                        {limit});
    std::vector<TxRow> out;
    for (int i = 0; i < r.rows(); ++i) out.push_back(tx_from_result(r, i));
    return out;
}

std::vector<TxRow> Ledger::block_txs(int64_t height) {
    Result r = db_.exec(std::string(kTxSelect) + "WHERE t.block_height = $1 ORDER BY t.block_index", {height});
    std::vector<TxRow> out;
    for (int i = 0; i < r.rows(); ++i) out.push_back(tx_from_result(r, i));
    return out;
}

static NodeRow node_from_result(const Result& r, int i) {
    NodeRow v;
    v.id = static_cast<int>(r.i64(i, "id"));
    v.name = r.str(i, "name");
    v.public_key_spki = r.str(i, "public_key_spki");
    v.private_key_pem = r.str(i, "private_key_pem");
    v.stake = r.i64(i, "stake");
    v.active = r.str(i, "active") == "t";
    v.slashed = r.str(i, "slashed") == "t";
    v.dishonest = r.str(i, "dishonest") == "t";
    v.balance = r.i64(i, "balance");
    v.locked = r.i64(i, "locked");
    return v;
}

std::vector<NodeRow> Ledger::ensure_nodes(int n, int64_t initial_stake) {
    auto l = db_.lock();
    for (int i = 1; i <= n; ++i) {
        char name[32];
        std::snprintf(name, sizeof(name), "node-%02d", i);
        if (db_.exec("SELECT 1 FROM nodes WHERE name = $1", {name}).rows() == 0) {
            auto kp = crypto::generate_p256();
            db_.exec(
                "INSERT INTO nodes (name, public_key_spki, private_key_pem, stake) VALUES ($1,$2,$3,$4)",
                {name, kp.public_spki_b64, kp.private_pem, initial_stake});
        }
    }
    Result r = db_.exec("SELECT * FROM nodes ORDER BY name LIMIT $1", {n});
    std::vector<NodeRow> out;
    for (int i = 0; i < r.rows(); ++i) out.push_back(node_from_result(r, i));
    return out;
}

std::vector<NodeRow> Ledger::nodes() {
    Result r = db_.exec("SELECT * FROM nodes ORDER BY name");
    std::vector<NodeRow> out;
    for (int i = 0; i < r.rows(); ++i) out.push_back(node_from_result(r, i));
    return out;
}

std::map<std::string, std::string> Ledger::node_keys() {
    Result r = db_.exec("SELECT name, public_key_spki FROM nodes");
    std::map<std::string, std::string> out;
    for (int i = 0; i < r.rows(); ++i) out[r.str(i, "name")] = r.str(i, "public_key_spki");
    return out;
}

int64_t Ledger::total_active_stake() {
    Result r = db_.exec("SELECT COALESCE(SUM(stake), 0) AS total FROM nodes WHERE active AND NOT slashed");
    return r.i64(0, "total");
}

bool Ledger::adjust_stake(int node_id, int64_t delta, std::string& err) {
    auto l = db_.lock();
    Result r = db_.exec("SELECT stake, slashed, locked FROM nodes WHERE id = $1", {node_id});
    if (r.rows() == 0) {
        err = "node not found";
        return false;
    }
    if (r.i64(0, "locked") > 0) {
        err = "stake is locked by the consensus round in progress";
        return false;
    }
    if (r.str(0, "slashed") == "t") {
        err = "node is slashed and cannot change its stake";
        return false;
    }
    int64_t new_stake = r.i64(0, "stake") + delta;
    if (new_stake < 0) {
        err = "stake cannot go negative";
        return false;
    }
    db_.exec("UPDATE nodes SET stake = $1 WHERE id = $2", {new_stake, node_id});
    return true;
}

bool Ledger::set_dishonest(int node_id, bool dishonest, std::string& err) {
    Result r = db_.exec("UPDATE nodes SET dishonest = $1 WHERE id = $2", {std::string(dishonest ? "true" : "false"), node_id});
    if (r.affected() != 1) {
        err = "node not found";
        return false;
    }
    return true;
}

void Ledger::slash(int node_id, int64_t amount, bool bar, const std::string& reason, const json& evidence,
                    std::optional<int64_t> block_height) {
    auto l = db_.lock();
    Result r = db_.exec("SELECT stake FROM nodes WHERE id = $1", {node_id});
    if (r.rows() == 0) return;
    int64_t before = r.i64(0, "stake");
    int64_t cut = std::min(amount, before);
    int64_t after = before - cut;
    if (bar) {
        db_.exec("UPDATE nodes SET stake = $1, active = false, slashed = true WHERE id = $2", {after, node_id});
    } else {
        db_.exec("UPDATE nodes SET stake = $1 WHERE id = $2", {after, node_id});
    }
    db_.exec(
        "INSERT INTO slashing_events (validator_id, reason, evidence, stake_before, stake_after, block_height) "
        "VALUES ($1,$2,$3::jsonb,$4,$5,$6)",
        {node_id, reason, evidence.dump(), before, after,
         block_height ? Param(*block_height) : Param(std::nullopt)});
}

std::vector<VoteRow> Ledger::block_votes(int64_t height) {
    Result r = db_.exec(
        "SELECT bv.validator_id, v.name AS validator_name, bv.signature, bv.stake_at_vote, bv.voted_at_ms "
        "FROM block_votes bv JOIN nodes v ON v.id = bv.validator_id WHERE bv.block_height = $1 ORDER BY bv.id",
        {height});
    std::vector<VoteRow> out;
    for (int i = 0; i < r.rows(); ++i) {
        VoteRow v;
        v.validator_id = static_cast<int>(r.i64(i, "validator_id"));
        v.validator_name = r.str(i, "validator_name");
        v.signature = r.str(i, "signature");
        v.stake_at_vote = r.i64(i, "stake_at_vote");
        v.voted_at_ms = r.i64(i, "voted_at_ms");
        out.push_back(v);
    }
    return out;
}

std::vector<chain::StakeEntry> Ledger::round_stake_snapshot(int64_t block_height) {
    Result r = db_.exec("SELECT participants::text AS participants FROM consensus_rounds WHERE block_height = $1",
                        {block_height});
    std::vector<chain::StakeEntry> out;
    if (r.rows() == 0) return out;
    try {
        json participants = json::parse(r.str(0, "participants"));
        for (const auto& p : participants) {
            chain::StakeEntry e;
            e.name = p.value("validator", "");
            e.stake = p.value("stake", 0LL);
            out.push_back(e);
        }
    } catch (...) {
        // malformed/missing snapshot surfaces as a proposer-selection mismatch in check_block
    }
    return out;
}

int Ledger::round_attempt(int64_t block_height) {
    Result r = db_.exec("SELECT attempt FROM consensus_rounds WHERE block_height = $1", {block_height});
    if (r.rows() == 0) return 0;
    return static_cast<int>(r.i64(0, "attempt"));
}

void Ledger::mature_pow_rewards(int64_t current_height) {
    // Mark matured rewards confirmed and credit each miner's balance in one statement.
    db_.exec(
        "WITH m AS (UPDATE pow_rewards SET confirmed = true, confirmed_at = now() "
        "           WHERE NOT confirmed AND height + 6 <= $1 RETURNING miner_id, amount) "
        "UPDATE nodes n SET balance = n.balance + s.total "
        "FROM (SELECT miner_id, SUM(amount) AS total FROM m GROUP BY miner_id) s WHERE n.id = s.miner_id",
        {current_height});
}

std::vector<RewardRow> Ledger::rewards() {
    Result r = db_.exec(
        "SELECT pr.height, pr.miner_id, n.name AS miner_name, pr.confirmed, pr.amount FROM pow_rewards pr "
        "JOIN nodes n ON n.id = pr.miner_id ORDER BY pr.height DESC");
    std::vector<RewardRow> out;
    for (int i = 0; i < r.rows(); ++i) {
        RewardRow w;
        w.height = r.i64(i, "height");
        w.miner_id = static_cast<int>(r.i64(i, "miner_id"));
        w.miner_name = r.str(i, "miner_name");
        w.confirmed = r.str(i, "confirmed") == "t";
        w.amount = r.i64(i, "amount");
        out.push_back(w);
    }
    return out;
}

std::vector<std::string> Ledger::check_block(const BlockRow& b, const std::string& expected_prev,
                                             const std::vector<TxRow>& txs,
                                             const std::map<std::string, std::string>& node_keys,
                                             const std::vector<chain::StakeEntry>& stake_snapshot, int attempt,
                                             const std::vector<VoteRow>& votes, bool check_artifacts) {
    std::vector<std::string> errs;
    const auto& h = b.header;

    std::string recomputed = chain::block_hash(h);
    if (recomputed != b.hash) errs.push_back("block hash mismatch: header hashes to " + recomputed.substr(0, 16) + "...");

    if (h.height == 0) {
        if (!(h.prev_hash == chain::kZeroHash && h.proposer == "genesis")) errs.push_back("invalid genesis block");
        return errs;
    }

    if (h.prev_hash != expected_prev) errs.push_back("prev_hash does not link to previous block");

    if (b.mode == "pow") {
        if (h.difficulty_hex_zeros < chain::kMinDifficultyHexZeros)
            errs.push_back("proof-of-work difficulty " + std::to_string(h.difficulty_hex_zeros) + " is below the minimum " +
                           std::to_string(chain::kMinDifficultyHexZeros));
        if (!chain::meets_difficulty(b.hash, h.difficulty_hex_zeros))
            errs.push_back("proof-of-work does not meet " + std::to_string(h.difficulty_hex_zeros) + " hex zeros");
    } else {
        std::string expected_proposer = chain::select_proposer(stake_snapshot, expected_prev, h.height, attempt);
        if (expected_proposer.empty() || expected_proposer != h.proposer)
            errs.push_back("proposer '" + h.proposer + "' was not the stake-weighted selection for this height");

        std::vector<chain::VoteStake> vote_stakes;
        for (const auto& v : votes) {
            vote_stakes.push_back({v.validator_name, v.stake_at_vote});
            auto vk = node_keys.find(v.validator_name);
            if (vk == node_keys.end()) {
                errs.push_back("vote from unregistered validator '" + v.validator_name + "'");
            } else if (!crypto::verify_p256(vk->second, b.hash, v.signature)) {
                errs.push_back("vote signature invalid for '" + v.validator_name + "'");
            }
        }
        for (auto& e : chain::check_vote_set(stake_snapshot, vote_stakes, b.total_stake, b.quorum_stake))
            errs.push_back(std::move(e));
    }

    auto pk = node_keys.find(h.proposer);
    if (pk == node_keys.end()) {
        errs.push_back("proposer '" + h.proposer + "' is not a registered node");
    } else if (!crypto::verify_p256(pk->second, b.hash, b.proposer_signature)) {
        errs.push_back("proposer signature invalid");
    }

    if (static_cast<int>(txs.size()) != b.tx_count) errs.push_back("transaction count mismatch");
    if (txs.empty()) errs.push_back("a block must contain at least one transaction");

    std::vector<std::string> ids;
    for (const auto& t : txs) {
        std::string short_id = t.tx_id.substr(0, 12);
        std::string recomputed_id = chain::tx_id(t.canonical, t.signature);
        if (recomputed_id != t.tx_id) errs.push_back("tx " + short_id + ": tx_id does not match its contents");
        ids.push_back(recomputed_id);  // merkle over what the data actually hashes to

        if (!crypto::verify_p256(t.auditor_spki, t.canonical, t.signature))
            errs.push_back("tx " + short_id + ": auditor signature invalid");

        chain::TxFields f;
        if (!chain::parse_canonical(t.canonical, f)) {
            errs.push_back("tx " + short_id + ": malformed canonical payload");
            continue;
        }
        if (f.auditor_fpr != crypto::fingerprint(t.auditor_spki))
            errs.push_back("tx " + short_id + ": auditor fingerprint mismatch");
        if (f.comment_hash != crypto::sha256_hex(t.comment))
            errs.push_back("tx " + short_id + ": reviewer comment altered");
        if (check_artifacts) {
            Result a = db_.exec("SELECT content FROM work_items WHERE id = $1", {f.work_item_id});
            if (a.rows() == 0) {
                errs.push_back("tx " + short_id + ": artifact missing");
            } else if (crypto::sha256_hex(a.bytea(0, "content")) != f.work_hash) {
                errs.push_back("tx " + short_id + ": off-chain artifact no longer matches signed work_hash");
            }
        }
    }
    if (chain::merkle_root(ids) != h.merkle_root) errs.push_back("merkle root mismatch");
    return errs;
}

void Ledger::commit_block(const BlockRow& b, const std::vector<TxRow>& txs,
                          const std::vector<chain::StakeEntry>& stake_snapshot, int attempt,
                          const std::vector<VoteRow>& votes, const json& round, int64_t proposer_reward) {
    Db::Transaction tx(db_);
    BlockRow prev = tip();
    if (b.header.height != prev.header.height + 1) throw DbError("stale block: height already taken");
    auto errs = check_block(b, prev.hash, txs, node_keys(), stake_snapshot, attempt, votes, false);
    if (!errs.empty()) throw DbError("block rejected: " + errs.front());

    const auto& h = b.header;
    db_.exec(
        "INSERT INTO blocks (height, hash, prev_hash, merkle_root, timestamp_ms, mode, nonce, "
        "difficulty_hex_zeros, proposer_name, proposer_signature, quorum_stake, total_stake, tx_count) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        {h.height, b.hash, h.prev_hash, h.merkle_root, h.timestamp_ms, b.mode, static_cast<int64_t>(h.nonce),
         h.difficulty_hex_zeros, h.proposer, b.proposer_signature, b.quorum_stake, b.total_stake,
         static_cast<int>(txs.size())});
    for (size_t i = 0; i < txs.size(); ++i) {
        Result u = db_.exec(
            "UPDATE transactions SET status='confirmed', block_height=$1, block_index=$2 "
            "WHERE tx_id=$3 AND status='mempool'",
            {h.height, static_cast<int>(i), txs[i].tx_id});
        if (u.affected() != 1) throw DbError("transaction " + txs[i].tx_id + " no longer in mempool");
        db_.exec("UPDATE work_items SET status='on_chain' WHERE id=$1", {txs[i].work_item_id});
    }
    for (const auto& v : votes) {
        db_.exec(
            "INSERT INTO block_votes (block_height, validator_id, signature, stake_at_vote, voted_at_ms) "
            "VALUES ($1,$2,$3,$4,$5)",
            {h.height, v.validator_id, v.signature, v.stake_at_vote, v.voted_at_ms});
    }
    db_.exec("UPDATE nodes SET blocks_proposed = blocks_proposed + 1 WHERE name=$1", {h.proposer});
    db_.exec(
        "INSERT INTO consensus_rounds (mode, attempt, proposer, participants, block_height, quorum_stake, "
        "total_stake, duration_ms, outcome) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'sealed')",
        {b.mode, attempt, h.proposer, round["participants"].dump(), h.height, b.quorum_stake, b.total_stake,
         round["duration_ms"].get<int64_t>()});
    if (b.mode == "pow") {
        Result miner = db_.exec("SELECT id FROM nodes WHERE name = $1", {h.proposer});
        if (miner.rows() == 1)
            db_.exec("INSERT INTO pow_rewards (height, miner_id, amount) VALUES ($1,$2,$3)",
                     {h.height, miner.i64(0, "id"), block_reward});
    } else if (proposer_reward > 0) {
        db_.exec("UPDATE nodes SET balance = balance + $1 WHERE name = $2", {proposer_reward, h.proposer});
    }
    mature_pow_rewards(h.height);
    tx.commit();
}

std::vector<ChainBlock> Ledger::export_chain() {
    auto l = db_.lock();
    Result r = db_.exec("SELECT * FROM blocks ORDER BY height");
    std::vector<ChainBlock> out;
    for (int i = 0; i < r.rows(); ++i) {
        ChainBlock cb;
        cb.block = block_from_result(r, i);
        int64_t height = cb.block.header.height;
        cb.txs = block_txs(height);
        cb.snapshot = round_stake_snapshot(height);
        cb.attempt = round_attempt(height);
        cb.votes = block_votes(height);
        out.push_back(std::move(cb));
    }
    return out;
}

json Ledger::validate_chain(const std::vector<ChainBlock>& chain_blocks,
                            const std::map<std::string, std::string>& keys, bool check_artifacts) {
    json blocks = json::array();
    std::string prev_hash;
    json first_bad = nullptr;
    int64_t expected_height = 0;

    for (const auto& cb : chain_blocks) {
        const BlockRow& b = cb.block;
        auto errs = check_block(b, prev_hash, cb.txs, keys, cb.snapshot, cb.attempt, cb.votes, check_artifacts);
        if (b.header.height != expected_height) errs.push_back("height gap in chain");
        // Once a block is broken, every later block inherits a broken history.
        if (errs.empty() && !first_bad.is_null()) errs.push_back("descends from invalid block " + first_bad.dump());
        if (!errs.empty() && first_bad.is_null()) first_bad = b.header.height;
        blocks.push_back({{"height", b.header.height}, {"hash", b.hash}, {"ok", errs.empty()}, {"errors", errs}});
        prev_hash = b.hash;
        ++expected_height;
    }
    return {{"ok", first_bad.is_null()}, {"height", expected_height - 1}, {"first_bad_height", first_bad},
            {"blocks", blocks}};
}

json Ledger::verify_chain() {
    auto l = db_.lock();
    return validate_chain(export_chain(), node_keys(), true);
}

std::optional<RewardRow> Ledger::reward(int64_t height) {
    for (auto& w : rewards())
        if (w.height == height) return w;
    return std::nullopt;
}

int64_t Ledger::tip_height() { return tip().header.height; }

void Ledger::lock_bets(const std::map<int, int64_t>& bets) {
    auto l = db_.lock();
    for (const auto& [id, amount] : bets) db_.exec("UPDATE nodes SET locked = $1 WHERE id = $2", {amount, id});
}

void Ledger::release_all_locks() { db_.exec("UPDATE nodes SET locked = 0"); }

void Ledger::log_event(const std::string& type, const std::string& message) {
    db_.exec("INSERT INTO event_log (type, message) VALUES ($1,$2)", {type, message});
}
