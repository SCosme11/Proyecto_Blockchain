#include "consensus.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <random>

#include "crypto.h"

using nlohmann::json;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

ConsensusCoordinator::ConsensusCoordinator(Ledger& ledger, Db& db, NodeNetwork& network, int max_tx_per_block,
                                           int64_t initial_stake)
    : ledger_(ledger), db_(db), network_(network), max_tx_(max_tx_per_block), initial_stake_(initial_stake) {}

ConsensusCoordinator::~ConsensusCoordinator() {
    stop();
    if (worker_.joinable()) worker_.join();
}

bool ConsensusCoordinator::start(const std::string& mode, int node_count, int difficulty_hex_zeros,
                                  int abstain_count, const std::string& punishment_rule, double alpha,
                                  std::string& err) {
    std::lock_guard<std::mutex> g(mu_);
    if (running_.load()) {
        err = "a consensus round is already running";
        return false;
    }
    if (worker_.joinable()) worker_.join();
    if (mode != "pow" && mode != "pos") {
        err = "mode must be 'pow' or 'pos'";
        return false;
    }
    if (mode == "pos" && punishment_rule != "A" && punishment_rule != "B") {
        err = "punishment_rule must be 'A' or 'B'";
        return false;
    }
    if (mode == "pos" && punishment_rule == "B" && (alpha <= 0 || alpha > 1)) {
        err = "alpha must satisfy 0 < alpha <= 1";
        return false;
    }

    auto node_rows = ledger_.ensure_nodes(node_count, initial_stake_);
    std::vector<NodeRow> eligible;
    for (auto& n : node_rows)
        if (n.active && !n.slashed) eligible.push_back(n);
    if (eligible.empty()) {
        err = "no active (non-slashed) nodes available";
        return false;
    }
    if (ledger_.mempool(max_tx_).empty()) {
        err = "no hay transacciones pendientes: firma al menos un trabajo antes de minar/proponer";
        return false;
    }
    BlockRow tip = ledger_.tip();
    network_.sync_registry(node_rows, tip.header.height, tip.hash);

    mode_ = mode;
    punishment_rule_ = punishment_rule;
    alpha_ = alpha;
    miners_.clear();
    voters_.clear();
    if (mode == "pow") {
        for (auto& n : eligible) {
            auto s = std::make_unique<MinerSlot>();
            s->node = n;
            miners_.push_back(std::move(s));
        }
    } else {
        int64_t total = 0;
        for (auto& n : eligible) total += n.stake;
        if (total <= 0) {
            err = "active nodes have zero total stake; stake some first";
            return false;
        }
        for (auto& n : eligible) {
            auto s = std::make_unique<VoterSlot>();
            s->node = n;
            voters_.push_back(std::move(s));
        }
    }

    found_ = false;
    stop_ = false;
    result_ = nullptr;
    attempts_log_ = json::array();
    finished_ms_ = 0;
    proposer_.clear();
    attempt_ = 0;
    quorum_stake_ = 0;
    started_ms_ = now_ms();
    ++round_no_;
    running_ = true;
    if (mode == "pow")
        worker_ = std::thread([this, difficulty_hex_zeros] { run_pow(difficulty_hex_zeros); });
    else
        worker_ = std::thread([this, abstain_count] { run_pos(abstain_count); });
    return true;
}

void ConsensusCoordinator::stop() {
    stop_ = true;
    found_ = true;
}

// ---------------------------------------------------------------- PoW ----------------------

void ConsensusCoordinator::mine(MinerSlot* slot, int miner_index, int n, chain::BlockHeader header,
                                 int difficulty_hex_zeros) {
    slot->state = PowMining;
    // The header hashed here must be byte-for-byte identical to the one the sealed block will
    // store (canonical_header includes `proposer`), otherwise the nonce found during the search
    // would not actually satisfy the difficulty target of the final, committed header.
    header.proposer = slot->node.name;
    const uint64_t kMaxAttempts = 2'000'000;  // safety cap: "no se resuelve en tiempo razonable"
    uint64_t nonce = static_cast<uint64_t>(miner_index);
    for (uint64_t idx = 0; idx < kMaxAttempts; ++idx, nonce += static_cast<uint64_t>(n)) {
        if (found_.load(std::memory_order_relaxed) || stop_.load(std::memory_order_relaxed)) {
            slot->state = PowStale;
            return;
        }
        header.nonce = nonce;
        std::string hash = chain::block_hash(header);
        slot->nonce.store(nonce, std::memory_order_relaxed);
        slot->attempts.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> g(slot->hash_mu);
            slot->last_hash = hash;
        }
        if (chain::meets_difficulty(hash, difficulty_hex_zeros)) {
            slot->winning_nonce = nonce;
            found_.store(true, std::memory_order_relaxed);
            slot->state = PowWinner;  // tentative; run_pow() keeps only the smallest-nonce winner
            return;
        }
    }
    slot->state = PowStale;  // exhausted its attempt budget without a solution
}

void ConsensusCoordinator::run_pow(int difficulty_hex_zeros) {
    std::lock_guard<std::mutex> chain_lock(ledger_.chain_mu);
    json result;
    try {
        BlockRow tip = ledger_.tip();
        std::vector<TxRow> txs = ledger_.mempool(max_tx_);
        if (txs.empty()) throw std::runtime_error("no pending transactions to mine");
        std::vector<std::string> ids;
        for (auto& t : txs) ids.push_back(t.tx_id);

        chain::BlockHeader hdr;
        hdr.height = tip.header.height + 1;
        hdr.prev_hash = tip.hash;
        hdr.merkle_root = chain::merkle_root(ids);
        hdr.timestamp_ms = now_ms();
        hdr.difficulty_hex_zeros = difficulty_hex_zeros;

        {
            std::lock_guard<std::mutex> g(mu_);
            height_ = hdr.height;
            prev_hash_ = hdr.prev_hash;
            tx_ids_ = ids;
        }

        int n = static_cast<int>(miners_.size());
        std::vector<std::thread> threads;
        for (size_t i = 0; i < miners_.size(); ++i)
            threads.emplace_back([this, slot = miners_[i].get(), i, n, hdr, difficulty_hex_zeros] {
                mine(slot, static_cast<int>(i), n, hdr, difficulty_hex_zeros);
            });
        for (auto& t : threads) t.join();

        // Tie-break: if more than one miner found a valid nonce in this round, the smallest
        // nonce wins -- well-defined because disjoint residue classes mean no two miners can
        // ever report the SAME nonce value, so this total-orders every tie.
        MinerSlot* winner = nullptr;
        for (auto& m : miners_)
            if (m->state.load() == PowWinner && (!winner || m->winning_nonce < winner->winning_nonce)) winner = m.get();
        if (winner)
            for (auto& m : miners_)
                if (m.get() != winner && m->state.load() == PowWinner) m->state = PowLate;

        int64_t duration = now_ms() - started_ms_;
        json participants = json::array();
        for (auto& m : miners_)
            participants.push_back({{"validator", m->node.name},
                                    {"stake", static_cast<int64_t>(m->attempts.load())},
                                    {"vote", (winner == m.get()) ? "yes" : "absent"}});

        if (!winner) {
            db_.exec(
                "INSERT INTO consensus_rounds (mode, attempt, proposer, participants, quorum_stake, total_stake, "
                "duration_ms, outcome) VALUES ('pow',0,NULL,$1,0,0,$2,'no_quorum')",
                {participants.dump(), duration});
            result = {{"outcome", "no_quorum"}, {"error", "ningún minero encontró un nonce válido (límite de intentos alcanzado)"}};
        } else {
            chain::BlockHeader whdr = hdr;
            whdr.proposer = winner->node.name;
            whdr.nonce = winner->winning_nonce;
            std::string hash = chain::block_hash(whdr);
            std::string sig = crypto::sign_p256(winner->node.private_key_pem, hash);

            BlockRow b;
            b.header = whdr;
            b.hash = hash;
            b.mode = "pow";
            b.proposer_signature = sig;
            b.quorum_stake = 0;
            b.total_stake = 0;
            b.tx_count = static_cast<int>(txs.size());
            json round = {{"participants", participants}, {"duration_ms", duration}};
            try {
                ledger_.commit_block(b, txs, {}, 0, {}, round);
                network_.broadcast(ledger_, b, txs, ledger_.node_keys(), {}, 0, {});
                result = {{"outcome", "sealed"},     {"proposer", winner->node.name},
                          {"height", b.header.height}, {"hash", b.hash},
                          {"nonce", whdr.nonce},        {"tx_count", b.tx_count}};
            } catch (const std::exception& e) {
                result = {{"outcome", "rejected"}, {"proposer", winner->node.name}, {"error", e.what()}};
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

// ---------------------------------------------------------------- PoS ----------------------

void ConsensusCoordinator::cast_vote(VoterSlot* slot, std::string block_hash, std::string proposer_sig,
                                      std::string proposer_pubkey) {
    slot->state = PosVoting;
    // An honest validator checks the proposal before voting: if the proposer's signature does
    // not verify (a dishonest proposal), it votes no by simply not signing.
    if (!crypto::verify_p256(proposer_pubkey, block_hash, proposer_sig)) {
        slot->state = PosAbstained;
        return;
    }
    thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> delay_ms(50, 300);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms(rng)));
    if (stop_.load() || slot->abstain) {
        slot->state = PosAbstained;
        return;
    }
    std::string sig = crypto::sign_p256(slot->node.private_key_pem, block_hash);
    {
        std::lock_guard<std::mutex> g(mu_);
        slot->signature = sig;
        slot->voted_at_ms = now_ms();
    }
    slot->state = PosVoted;
}

void ConsensusCoordinator::run_pos(int abstain_count) {
    std::lock_guard<std::mutex> chain_lock(ledger_.chain_mu);
    json result = nullptr;
    try {
        BlockRow tip = ledger_.tip();
        std::vector<TxRow> txs = ledger_.mempool(max_tx_);
        if (txs.empty()) throw std::runtime_error("no pending transactions to propose");
        std::vector<std::string> ids;
        for (auto& t : txs) ids.push_back(t.tx_id);
        std::string merkle = chain::merkle_root(ids);
        int64_t ts = now_ms();
        int64_t height = tip.header.height + 1;

        {
            std::lock_guard<std::mutex> g(mu_);
            height_ = height;
            prev_hash_ = tip.hash;
            tx_ids_ = ids;
        }

        // Remaining eligible pool for this round; shrinks by one every time a drawn proposer
        // turns out to be dishonest and gets slashed ("se repite el sorteo con los
        // validadores restantes").
        std::vector<VoterSlot*> pool;
        for (auto& v : voters_) pool.push_back(v.get());

        int attempt = 0;
        while (!stop_.load()) {
            std::vector<chain::StakeEntry> stake_snapshot;
            int64_t total = 0;
            for (auto* v : pool) {
                stake_snapshot.push_back({v->node.name, v->node.stake});
                total += v->node.stake;
            }
            if (pool.empty() || total <= 0) {
                result = {{"outcome", "no_quorum"}, {"error", "se agotó el conjunto de validadores sin sellar el bloque"}};
                break;
            }
            total_stake_ = total;
            quorum_threshold_ = chain::quorum_threshold(total);
            attempt_ = attempt;

            std::string proposer_name = chain::select_proposer(stake_snapshot, tip.hash, height, attempt);
            VoterSlot* proposer_slot = nullptr;
            for (auto* v : pool)
                if (v->node.name == proposer_name) proposer_slot = v;
            proposer_ = proposer_name;
            if (!proposer_slot) {
                result = {{"outcome", "error"}, {"error", "sorteo produjo un proponente desconocido"}};
                break;
            }

            chain::BlockHeader hdr;
            hdr.height = height;
            hdr.prev_hash = tip.hash;
            hdr.merkle_root = merkle;
            hdr.timestamp_ms = ts;
            hdr.proposer = proposer_name;
            std::string block_hash = chain::block_hash(hdr);

            bool dishonest = proposer_slot->node.dishonest;
            std::string proposer_sig = crypto::sign_p256(
                proposer_slot->node.private_key_pem, dishonest ? block_hash + "|corrupted" : block_hash);

            for (auto* v : pool) {
                v->state = PosIdle;
                v->signature.clear();
                v->voted_at_ms = 0;
                v->abstain = false;
            }
            std::vector<VoterSlot*> order(pool);
            std::sort(order.begin(), order.end(), [](VoterSlot* a, VoterSlot* b) { return a->node.stake < b->node.stake; });
            int ab = std::min<int>(abstain_count, static_cast<int>(order.size()));
            for (int i = 0; i < ab; ++i) order[i]->abstain = true;

            std::vector<std::thread> threads;
            for (auto* v : pool)
                if (v != proposer_slot)
                    threads.emplace_back([this, v, block_hash, proposer_sig, pk = proposer_slot->node.public_key_spki] {
                        cast_vote(v, block_hash, proposer_sig, pk);
                    });
            for (auto& t : threads) t.join();

            // `participants` must iterate `pool` in the exact same order as `stake_snapshot`
            // above (NOT proposer-first): `chain::select_proposer` is order-sensitive, and
            // verify_chain later rebuilds its own stake_snapshot by parsing this JSON back in
            // array order, to recompute and check the same draw. Any reordering here would make
            // a perfectly honest block fail re-verification.
            int64_t quorum = 0;
            std::vector<VoteRow> votes;
            json participants = json::array();
            for (auto* v : pool) {
                if (v == proposer_slot) {
                    participants.push_back({{"validator", v->node.name},
                                            {"stake", v->node.stake},
                                            {"vote", dishonest ? "dishonest_proposal" : "proposer"}});
                    // An honest proposer implicitly backs its own proposal: it counts toward
                    // quorum the same way any other "yes" vote does, so it must also appear in
                    // `votes` (using its existing block signature) -- otherwise check_block's
                    // recomputed sum of votes would never match `quorum`.
                    if (!dishonest) {
                        votes.push_back({v->node.id, v->node.name, proposer_sig, v->node.stake, ts});
                        quorum += v->node.stake;
                    }
                    continue;
                }
                int st = v->state.load();
                participants.push_back(
                    {{"validator", v->node.name}, {"stake", v->node.stake}, {"vote", st == PosVoted ? "yes" : "absent"}});
                if (st == PosVoted) {
                    votes.push_back({v->node.id, v->node.name, v->signature, v->node.stake, v->voted_at_ms});
                    quorum += v->node.stake;
                }
            }
            quorum_stake_ = quorum;

            int64_t duration = now_ms() - started_ms_;
            json round_log = {{"attempt", attempt},         {"proposer", proposer_name}, {"dishonest", dishonest},
                               {"quorum_stake", quorum},      {"total_stake", total_stake_}};

            if (quorum >= quorum_threshold_) {
                BlockRow b;
                b.header = hdr;
                b.hash = block_hash;
                b.mode = "pos";
                b.proposer_signature = proposer_sig;
                b.quorum_stake = quorum;
                b.total_stake = total_stake_;
                b.tx_count = static_cast<int>(txs.size());
                json round = {{"participants", participants}, {"duration_ms", duration}};
                try {
                    ledger_.commit_block(b, txs, stake_snapshot, attempt, votes, round);
                    network_.broadcast(ledger_, b, txs, ledger_.node_keys(), stake_snapshot, attempt, votes);
                    round_log["outcome"] = "sealed";
                    attempts_log_.push_back(round_log);
                    result = {{"outcome", "sealed"},        {"proposer", proposer_name},
                              {"height", b.header.height},   {"hash", b.hash},
                              {"quorum_stake", quorum},       {"total_stake", total_stake_},
                              {"tx_count", b.tx_count},       {"attempts", attempt + 1}};
                } catch (const std::exception& e) {
                    round_log["outcome"] = "rejected";
                    attempts_log_.push_back(round_log);
                    result = {{"outcome", "rejected"}, {"proposer", proposer_name}, {"error", e.what()}};
                }
                break;
            }

            if (!dishonest) {
                // A genuinely valid proposal simply didn't gather enough participation this
                // round (e.g. simulated abstentions) -- nothing to punish, the round just ends.
                round_log["outcome"] = "no_quorum";
                attempts_log_.push_back(round_log);
                result = {{"outcome", "no_quorum"},
                          {"error", "quórum no alcanzado: " + std::to_string(quorum) + "/" + std::to_string(quorum_threshold_)}};
                break;
            }

            // Caught: the dishonest proposer is slashed and removed from the pool, then the
            // sorteo repeats with an incremented attempt ("intento") over the remainder.
            db_.exec(
                "INSERT INTO consensus_rounds (mode, attempt, proposer, participants, quorum_stake, total_stake, "
                "duration_ms, outcome) VALUES ('pos',$1,$2,$3,$4,$5,$6,'rejected_retry')",
                {attempt, proposer_name, participants.dump(), quorum, total_stake_, duration});
            round_log["outcome"] = "rejected_retry";
            attempts_log_.push_back(round_log);

            // Punishment rule (A): forfeit the whole stake and bar the node from future rounds.
            // Punishment rule (B): forfeit only a fraction alpha of its own stake ("pierde ...
            // un porcentaje", per the guide) and stay eligible for later rounds -- there is no
            // monetary transaction value in this domain to base the cap on, so alpha applies
            // directly to the proposer's own stake instead of a transaction-value proxy.
            bool bar = punishment_rule_ == "A";
            int64_t full_stake = proposer_slot->node.stake;
            int64_t cut = bar ? full_stake : static_cast<int64_t>(std::ceil(alpha_ * static_cast<double>(full_stake)));
            json evidence = {{"block_hash", block_hash}, {"attempt", attempt}, {"punishment_rule", punishment_rule_}};
            ledger_.slash(proposer_slot->node.id, cut, bar, "dishonest_proposal", evidence,
                         std::optional<int64_t>(height));
            pool.erase(std::remove(pool.begin(), pool.end(), proposer_slot), pool.end());
            ++attempt;
        }
        if (result.is_null()) result = {{"outcome", "no_quorum"}, {"error", "round stopped"}};
    } catch (const std::exception& e) {
        result = {{"outcome", "error"}, {"error", e.what()}};
    }

    std::lock_guard<std::mutex> g(mu_);
    result_ = result;
    finished_ms_ = now_ms();
    running_ = false;
}

// ---------------------------------------------------------------- snapshot -----------------

json ConsensusCoordinator::snapshot() {
    std::lock_guard<std::mutex> g(mu_);
    int64_t end = finished_ms_ ? finished_ms_ : now_ms();
    json j = {{"round", round_no_},
              {"running", running_.load()},
              {"mode", mode_},
              {"height", height_},
              {"prev_hash", prev_hash_},
              {"tx_ids", tx_ids_},
              {"elapsed_ms", round_no_ ? end - started_ms_ : 0},
              {"result", result_}};
    if (mode_ == "pow") {
        json miners = json::array();
        for (auto& m : miners_) {
            std::string lh;
            {
                std::lock_guard<std::mutex> hg(m->hash_mu);
                lh = m->last_hash;
            }
            int st = m->state.load();
            const char* status = st == PowMining ? "mining" : st == PowWinner ? "winner" : st == PowLate ? "late"
                                 : st == PowStale ? "stale" : "idle";
            miners.push_back({{"name", m->node.name},
                              {"nonce", m->nonce.load()},
                              {"attempts", m->attempts.load()},
                              {"last_hash", lh.empty() ? json(nullptr) : json(lh)},
                              {"status", status}});
        }
        j["miners"] = miners;
    } else {
        j["proposer"] = proposer_;
        j["attempt"] = attempt_;
        j["total_stake"] = total_stake_;
        j["quorum_threshold"] = quorum_threshold_;
        j["quorum_stake"] = quorum_stake_;
        j["attempts_log"] = attempts_log_;
        json vs = json::array();
        for (auto& v : voters_) {
            int st = v->state.load();
            const char* status =
                st == PosVoting ? "voting" : st == PosVoted ? "voted" : st == PosAbstained ? "abstained" : "idle";
            vs.push_back({{"name", v->node.name},
                         {"stake", v->node.stake},
                         {"dishonest", v->node.dishonest},
                         {"status", status},
                         {"signature", v->signature.empty() ? json(nullptr) : json(v->signature)}});
        }
        j["validators"] = vs;
    }
    return j;
}
