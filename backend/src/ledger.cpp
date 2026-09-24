#include "ledger.h"

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
    b.header.difficulty_bits = static_cast<int>(r.i64(row, "difficulty_bits"));
    b.header.miner = r.str(row, "miner_name");
    b.header.nonce = static_cast<uint64_t>(r.i64(row, "nonce"));
    b.hash = r.str(row, "hash");
    b.miner_signature = r.str(row, "miner_signature");
    b.tx_count = static_cast<int>(r.i64(row, "tx_count"));
    return b;
}

void Ledger::apply_schema(const std::string& path) {
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
        "INSERT INTO blocks (height, hash, prev_hash, merkle_root, timestamp_ms, difficulty_bits, nonce, "
        "miner_name, miner_signature, tx_count) VALUES (0,$1,$2,$3,$4,0,0,$5,'',0)",
        {chain::block_hash(g), g.prev_hash, g.merkle_root, g.timestamp_ms, g.miner});
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

std::vector<MinerRow> Ledger::ensure_miners(int n) {
    auto l = db_.lock();
    for (int i = 1; i <= n; ++i) {
        char name[32];
        std::snprintf(name, sizeof(name), "miner-%02d", i);
        if (db_.exec("SELECT 1 FROM miners WHERE name = $1", {name}).rows() == 0) {
            auto kp = crypto::generate_p256();
            db_.exec("INSERT INTO miners (name, public_key_spki, private_key_pem) VALUES ($1,$2,$3)",
                     {name, kp.public_spki_b64, kp.private_pem});
        }
    }
    Result r = db_.exec("SELECT * FROM miners ORDER BY name LIMIT $1", {n});
    std::vector<MinerRow> out;
    for (int i = 0; i < r.rows(); ++i) {
        MinerRow m;
        m.id = static_cast<int>(r.i64(i, "id"));
        m.name = r.str(i, "name");
        m.public_key_spki = r.str(i, "public_key_spki");
        m.private_key_pem = r.str(i, "private_key_pem");
        out.push_back(m);
    }
    return out;
}

std::map<std::string, std::string> Ledger::miner_keys() {
    Result r = db_.exec("SELECT name, public_key_spki FROM miners");
    std::map<std::string, std::string> out;
    for (int i = 0; i < r.rows(); ++i) out[r.str(i, "name")] = r.str(i, "public_key_spki");
    return out;
}

std::vector<std::string> Ledger::check_block(const BlockRow& b, const std::string& expected_prev,
                                             const std::vector<TxRow>& txs,
                                             const std::map<std::string, std::string>& miner_keys,
                                             bool check_artifacts) {
    std::vector<std::string> errs;
    const auto& h = b.header;

    std::string recomputed = chain::block_hash(h);
    if (recomputed != b.hash) errs.push_back("block hash mismatch: header hashes to " + recomputed.substr(0, 16) + "...");

    if (h.height == 0) {
        if (!(h.prev_hash == chain::kZeroHash && h.miner == "genesis")) errs.push_back("invalid genesis block");
        return errs;
    }

    if (h.prev_hash != expected_prev) errs.push_back("prev_hash does not link to previous block");
    if (!chain::meets_difficulty(b.hash, h.difficulty_bits))
        errs.push_back("proof-of-work does not meet " + std::to_string(h.difficulty_bits) + " bits");

    auto mk = miner_keys.find(h.miner);
    if (mk == miner_keys.end()) {
        errs.push_back("miner '" + h.miner + "' is not a registered (permissioned) miner");
    } else if (!crypto::verify_p256(mk->second, b.hash, b.miner_signature)) {
        errs.push_back("miner signature invalid");
    }

    if (static_cast<int>(txs.size()) != b.tx_count) errs.push_back("transaction count mismatch");

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

void Ledger::commit_block(const BlockRow& b, const std::vector<TxRow>& txs, const json& round) {
    Db::Transaction tx(db_);
    BlockRow prev = tip();
    if (b.header.height != prev.header.height + 1) throw DbError("stale block: height already taken");
    auto errs = check_block(b, prev.hash, txs, miner_keys(), false);
    if (!errs.empty()) throw DbError("block rejected: " + errs.front());

    const auto& h = b.header;
    db_.exec(
        "INSERT INTO blocks (height, hash, prev_hash, merkle_root, timestamp_ms, difficulty_bits, nonce, "
        "miner_name, miner_signature, tx_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        {h.height, b.hash, h.prev_hash, h.merkle_root, h.timestamp_ms, h.difficulty_bits,
         static_cast<int64_t>(h.nonce), h.miner, b.miner_signature, static_cast<int>(txs.size())});
    for (size_t i = 0; i < txs.size(); ++i) {
        Result u = db_.exec(
            "UPDATE transactions SET status='confirmed', block_height=$1, block_index=$2 "
            "WHERE tx_id=$3 AND status='mempool'",
            {h.height, static_cast<int>(i), txs[i].tx_id});
        if (u.affected() != 1) throw DbError("transaction " + txs[i].tx_id + " no longer in mempool");
        db_.exec("UPDATE work_items SET status='on_chain' WHERE id=$1", {txs[i].work_item_id});
    }
    db_.exec("UPDATE miners SET blocks_mined = blocks_mined + 1 WHERE name=$1", {h.miner});
    db_.exec(
        "INSERT INTO mining_rounds (difficulty_bits, participants, winner, block_height, duration_ms, "
        "hashes_total, outcome) VALUES ($1,$2,$3,$4,$5,$6,'sealed')",
        {h.difficulty_bits, round["participants"].dump(), h.miner, h.height,
         round["duration_ms"].get<int64_t>(), round["hashes_total"].get<int64_t>()});
    tx.commit();
}

json Ledger::verify_chain() {
    auto l = db_.lock();
    Result r = db_.exec("SELECT * FROM blocks ORDER BY height");
    auto keys = miner_keys();
    json blocks = json::array();
    std::string prev_hash;
    json first_bad = nullptr;
    int64_t expected_height = 0;

    for (int i = 0; i < r.rows(); ++i) {
        BlockRow b = block_from_result(r, i);
        auto txs = block_txs(b.header.height);
        auto errs = check_block(b, prev_hash, txs, keys, true);
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
