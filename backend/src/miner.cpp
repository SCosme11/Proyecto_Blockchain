#include "miner.h"

#include <charconv>
#include <chrono>
#include <cmath>

#include "crypto.h"

using nlohmann::json;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static const char* state_name(int s) {
    switch (s) {
        case 1: return "mining";
        case 2: return "winner";
        case 3: return "late";   // found a valid block after the winner -> orphaned
        case 4: return "stale";  // stopped; its candidate no longer extends the tip
        default: return "idle";
    }
}

MiningCoordinator::MiningCoordinator(Ledger& ledger, Db& db, int max_tx_per_block)
    : ledger_(ledger), db_(db), max_tx_(max_tx_per_block) {}

MiningCoordinator::~MiningCoordinator() {
    stop();
    if (worker_.joinable()) worker_.join();
}

bool MiningCoordinator::start(int miner_count, int difficulty_bits, std::string& err) {
    std::lock_guard<std::mutex> g(mu_);
    if (running_.load()) {
        err = "a mining round is already running";
        return false;
    }
    if (worker_.joinable()) worker_.join();

    std::vector<MinerRow> miners = ledger_.ensure_miners(miner_count);
    slots_.clear();
    for (auto& m : miners) {
        auto s = std::make_unique<Slot>();
        s->miner = m;
        slots_.push_back(std::move(s));
    }
    winner_ = -1;
    found_ = false;
    stop_ = false;
    difficulty_ = difficulty_bits;
    started_ms_ = now_ms();
    finished_ms_ = 0;
    result_ = nullptr;
    ++round_no_;
    running_ = true;
    worker_ = std::thread([this, difficulty_bits] { run_round(difficulty_bits); });
    return true;
}

void MiningCoordinator::stop() {
    stop_ = true;
    found_ = true;  // makes all miner loops exit
}

void MiningCoordinator::mine(size_t idx, const chain::BlockHeader& header) {
    Slot& slot = *slots_[idx];
    crypto::MidstateHasher hasher(chain::header_prefix(header));  // header minus nonce, hashed once
    slot.state = Mining;

    char buf[24];
    unsigned char digest[32];
    for (uint64_t nonce = 0;; ++nonce) {
        if ((nonce & 0x3FF) == 0) {
            slot.hashes.store(nonce, std::memory_order_relaxed);
            if (found_.load(std::memory_order_relaxed)) {
                slot.state = Stale;
                return;
            }
        }
        auto res = std::to_chars(buf, buf + sizeof(buf), nonce);
        hasher.hash(buf, static_cast<size_t>(res.ptr - buf), digest);
        if (crypto::leading_zero_bits(digest, 32) >= header.difficulty_bits) {
            slot.hashes.store(nonce + 1, std::memory_order_relaxed);
            bool expected = false;
            bool won = found_.compare_exchange_strong(expected, true);
            std::lock_guard<std::mutex> g(mu_);
            slot.nonce = nonce;
            slot.hash = crypto::to_hex(digest, 32);
            slot.found_at_ms = now_ms();
            if (won && !stop_.load()) {
                winner_ = static_cast<int>(idx);
                slot.state = Winner;
            } else {
                slot.state = Late;
            }
            return;
        }
    }
}

void MiningCoordinator::run_round(int difficulty_bits) {
    std::lock_guard<std::mutex> chain_lock(ledger_.chain_mu);
    json result;
    try {
        BlockRow tip = ledger_.tip();
        std::vector<TxRow> txs = ledger_.mempool(max_tx_);
        std::vector<std::string> ids;
        for (auto& t : txs) ids.push_back(t.tx_id);

        chain::BlockHeader tmpl;
        tmpl.height = tip.header.height + 1;
        tmpl.prev_hash = tip.hash;
        tmpl.merkle_root = chain::merkle_root(ids);
        tmpl.difficulty_bits = difficulty_bits;
        {
            std::lock_guard<std::mutex> g(mu_);
            height_ = tmpl.height;
            prev_hash_ = tmpl.prev_hash;
            tx_ids_ = ids;
        }

        // Each miner builds its own candidate header (own name + timestamp), kept so the
        // winner's block can be reproduced exactly after the race.
        std::vector<chain::BlockHeader> headers(slots_.size(), tmpl);
        std::vector<std::thread> threads;
        for (size_t i = 0; i < slots_.size(); ++i) {
            headers[i].miner = slots_[i]->miner.name;
            headers[i].timestamp_ms = now_ms();
            threads.emplace_back([this, i, &headers] { mine(i, headers[i]); });
        }
        for (auto& t : threads) t.join();

        int64_t duration = now_ms() - started_ms_;
        uint64_t total = 0;
        json participants = json::array();
        for (auto& s : slots_) {
            total += s->hashes.load();
            participants.push_back({{"miner", s->miner.name},
                                    {"hashes", s->hashes.load()},
                                    {"status", state_name(s->state.load())}});
        }

        int w;
        {
            std::lock_guard<std::mutex> g(mu_);
            w = winner_;
        }
        if (w < 0) {
            db_.exec(
                "INSERT INTO mining_rounds (difficulty_bits, participants, duration_ms, hashes_total, outcome) "
                "VALUES ($1,$2,$3,$4,'stopped')",
                {difficulty_bits, participants.dump(), duration, static_cast<int64_t>(total)});
            result = {{"outcome", "stopped"}};
        } else {
            Slot& win = *slots_[w];
            BlockRow b;
            b.header = headers[w];
            b.header.nonce = win.nonce;
            b.hash = chain::block_hash(b.header);
            b.miner_signature = crypto::sign_p256(win.miner.private_key_pem, b.hash);
            b.tx_count = static_cast<int>(txs.size());
            json round = {{"participants", participants},
                          {"duration_ms", duration},
                          {"hashes_total", static_cast<int64_t>(total)}};
            try {
                ledger_.commit_block(b, txs, round);
                result = {{"outcome", "sealed"},
                          {"winner", win.miner.name},
                          {"height", b.header.height},
                          {"hash", b.hash},
                          {"nonce", win.nonce},
                          {"tx_count", b.tx_count}};
            } catch (const std::exception& e) {
                db_.exec(
                    "INSERT INTO mining_rounds (difficulty_bits, participants, winner, duration_ms, hashes_total, "
                    "outcome) VALUES ($1,$2,$3,$4,$5,'rejected')",
                    {difficulty_bits, participants.dump(), win.miner.name, duration, static_cast<int64_t>(total)});
                result = {{"outcome", "rejected"}, {"winner", win.miner.name}, {"error", e.what()}};
            }
        }
    } catch (const std::exception& e) {
        result = {{"outcome", "error"}, {"error", e.what()}};
    }

    std::lock_guard<std::mutex> g(mu_);
    result_ = result;
    finished_ms_ = now_ms();
    running_ = false;
}

json MiningCoordinator::snapshot() {
    std::lock_guard<std::mutex> g(mu_);
    int64_t end = finished_ms_ ? finished_ms_ : now_ms();
    double secs = std::max(0.001, (end - started_ms_) / 1000.0);
    json miners = json::array();
    uint64_t total = 0;
    for (size_t i = 0; i < slots_.size(); ++i) {
        auto& s = *slots_[i];
        uint64_t h = s.hashes.load(std::memory_order_relaxed);
        total += h;
        miners.push_back({{"name", s.miner.name},
                          {"hashes", h},
                          {"hashrate", h / secs},
                          {"status", state_name(s.state.load())},
                          {"nonce", s.hash.empty() ? json(nullptr) : json(s.nonce)},
                          {"hash", s.hash.empty() ? json(nullptr) : json(s.hash)}});
    }
    return {{"round", round_no_},
            {"running", running_.load()},
            {"difficulty_bits", difficulty_},
            {"expected_hashes", std::pow(2.0, difficulty_)},
            {"height", height_},
            {"prev_hash", prev_hash_},
            {"tx_ids", tx_ids_},
            {"elapsed_ms", round_no_ ? end - started_ms_ : 0},
            {"total_hashes", total},
            {"total_hashrate", total / secs},
            {"miners", miners},
            {"result", result_}};
}
