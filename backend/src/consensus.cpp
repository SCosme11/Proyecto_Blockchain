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

namespace {

constexpr int kMinMiners = 10;  // the guide: between 10 and 20 miners

uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char ch : s) {
        h ^= ch;
        h *= 1099511628211ULL;
    }
    return h;
}

// Frees every locked bet when a PoS round ends, whichever way it ends.
struct BetRelease {
    Ledger& ledger;
    ~BetRelease() {
        try {
            ledger.release_all_locks();
        } catch (...) {
        }
    }
};

}  // namespace

ConsensusCoordinator::ConsensusCoordinator(Ledger& ledger, Db& db, NodeNetwork& network, Config cfg)
    : ledger_(ledger), db_(db), network_(network), cfg_(cfg) {}

ConsensusCoordinator::~ConsensusCoordinator() {
    stop();
    if (worker_.joinable()) worker_.join();
}

bool ConsensusCoordinator::start(const ConsensusParams& p, std::string& err, int& status) {
    std::lock_guard<std::mutex> g(mu_);
    status = 409;
    if (running_.load()) {
        err = "a consensus round is already running";
        return false;
    }
    if (worker_.joinable()) worker_.join();
    status = 400;
    if (p.mode != "pow" && p.mode != "pos") {
        err = "mode must be 'pow' or 'pos'";
        return false;
    }
    if (p.mode == "pos" && p.punishment_rule != "A" && p.punishment_rule != "B") {
        err = "punishment_rule must be 'A' or 'B'";
        return false;
    }
    if (p.mode == "pos" && p.punishment_rule == "B" && (p.alpha <= 0 || p.alpha > 1)) {
        err = "alpha must satisfy 0 < alpha <= 1";
        return false;
    }
    if (p.bet_pct < 1 || p.bet_pct > 100) {
        err = "bet_pct must be between 1 and 100";
        return false;
    }
    if (p.vote_window_ms < 0 || p.vote_window_ms > 30000) {
        err = "vote_window_ms must be between 0 and 30000";
        return false;
    }
    if (p.validators < 0) {
        err = "validators must be >= 0 (0 = every node with stake)";
        return false;
    }

    status = 409;
    auto node_rows = ledger_.ensure_nodes(p.node_count, cfg_.initial_stake);
    std::vector<NodeRow> eligible;
    for (auto& n : node_rows)
        if (n.active && !n.slashed) eligible.push_back(n);
    if (eligible.empty()) {
        err = "no active (non-slashed) nodes available: reset the simulation or use punishment rule B";
        return false;
    }
    if (p.mode == "pow" && static_cast<int>(eligible.size()) < kMinMiners) {
        err = "solo quedan " + std::to_string(eligible.size()) + " mineros elegibles (< " + std::to_string(kMinMiners) +
              "): hay nodos inhabilitados por castigo; reinicia la simulación";
        return false;
    }
    if (ledger_.mempool(cfg_.max_tx_per_block).empty()) {
        err = "no hay transacciones pendientes: firma al menos un trabajo antes de minar/proponer";
        return false;
    }

    uint64_t seed = p.has_seed ? p.seed
                    : cfg_.default_seed ? cfg_.default_seed
                                         : static_cast<uint64_t>(now_ms()) * 2654435761ULL + (round_counter_seed_++);

    std::vector<std::unique_ptr<MinerSlot>> miners;
    std::vector<std::unique_ptr<VoterSlot>> voters;
    std::map<int, int64_t> locks;
    if (p.mode == "pow") {
        for (auto& n : eligible) {
            auto s = std::make_unique<MinerSlot>();
            s->node = n;
            miners.push_back(std::move(s));
        }
    } else {
        std::vector<NodeRow> candidates;
        for (auto& n : eligible)
            if (n.stake > 0) candidates.push_back(n);
        if (candidates.empty()) {
            err = "ningún nodo tiene stake (saldo) para apostar: asigna stake a algún nodo primero";
            return false;
        }
        // Explicit bets must be 0 < a_i <= the node's stake ("apuesta mayor al saldo, cero o negativa").
        status = 400;
        for (const auto& [name, amount] : p.bets) {
            auto it = std::find_if(node_rows.begin(), node_rows.end(), [&](const NodeRow& n) { return n.name == name; });
            if (it == node_rows.end()) {
                err = "apuesta de '" + name + "': ese nodo no existe";
                return false;
            }
            if (amount <= 0) {
                err = "apuesta de '" + name + "' inválida: debe ser mayor que 0";
                return false;
            }
            if (amount > it->stake) {
                err = "apuesta de '" + name + "' inválida: " + std::to_string(amount) + " excede su saldo (" +
                      std::to_string(it->stake) + ")";
                return false;
            }
        }
        status = 409;
        if (p.validators > 0) {
            if (p.validators > static_cast<int>(candidates.size())) {
                err = "se pidieron " + std::to_string(p.validators) + " validadores pero solo " +
                      std::to_string(candidates.size()) + " nodos tienen stake";
                return false;
            }
            std::mt19937_64 rng(seed);
            std::shuffle(candidates.begin(), candidates.end(), rng);
            candidates.resize(p.validators);
            std::sort(candidates.begin(), candidates.end(), [](const NodeRow& a, const NodeRow& b) { return a.name < b.name; });
        }
        for (auto& n : candidates) {
            auto s = std::make_unique<VoterSlot>();
            s->node = n;
            auto it = p.bets.find(n.name);
            if (it != p.bets.end()) s->bet = it->second;
            else s->bet = std::max<int64_t>(1, (n.stake * p.bet_pct + 99) / 100);
            locks[n.id] = s->bet;
            voters.push_back(std::move(s));
        }
    }

    BlockRow tip = ledger_.tip();
    network_.sync_registry(ledger_, node_rows);
    if (!locks.empty()) ledger_.lock_bets(locks);

    mode_ = p.mode;
    punishment_rule_ = p.punishment_rule;
    alpha_ = p.alpha;
    vote_window_ms_ = p.vote_window_ms;
    seed_ = seed;
    miners_ = std::move(miners);
    voters_ = std::move(voters);
    pool_names_.clear();
    external_votes_.clear();
    found_ = false;
    stop_ = false;
    result_ = nullptr;
    attempts_log_ = json::array();
    phase_log_ = json::array();
    finished_ms_ = 0;
    proposer_.clear();
    attempt_ = 0;
    quorum_stake_ = 0;
    total_stake_ = 0;
    quorum_threshold_ = 0;
    height_ = tip.header.height + 1;
    prev_hash_ = tip.hash;
    tx_ids_.clear();
    started_ms_ = now_ms();
    ++round_no_;
    phase_ = p.mode == "pos" ? "APUESTAS" : "MINANDO";
    phase_log_.push_back({{"phase", phase_}, {"at_ms", 0}});
    running_ = true;
    if (p.mode == "pow")
        worker_ = std::thread([this, d = p.difficulty_hex_zeros] { run_pow(d); });
    else
        worker_ = std::thread([this, a = p.abstain_count] { run_pos(a); });
    return true;
}

void ConsensusCoordinator::stop() {
    stop_ = true;
    found_ = true;
}

void ConsensusCoordinator::set_phase(const std::string& phase) {
    std::lock_guard<std::mutex> g(mu_);
    phase_ = phase;
    phase_log_.push_back({{"phase", phase}, {"at_ms", now_ms() - started_ms_}});
}

void ConsensusCoordinator::phase_pause() {
    for (int waited = 0; waited < cfg_.phase_delay_ms && !stop_.load(); waited += 25)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
}

void ConsensusCoordinator::publish_block(const ChainBlock& cb) {
    auto refusals = network_.broadcast(ledger_, cb, ledger_.node_keys());
    for (const auto& r : refusals) ledger_.log_event("node_reject", r);
}

bool ConsensusCoordinator::submit_vote(const std::string& validator, const std::string& vote, std::string& message,
                                        int& status) {
    if (vote != "yes" && vote != "no") {
        status = 400;
        message = "vote must be 'yes' or 'no'";
        return false;
    }
    std::string log;
    bool ok = [&]() {
        std::lock_guard<std::mutex> g(mu_);
        auto fail = [&](int st, const std::string& m, bool audit) {
            status = st;
            message = m;
            if (audit) log = "Voto rechazado de " + validator + ": " + m;
            return false;
        };
        if (!running_.load() || mode_ != "pos" || phase_ != "VOTACION")
            return fail(409, "no hay una votación abierta en este momento", false);
        VoterSlot* slot = nullptr;
        for (auto& v : voters_)
            if (v->node.name == validator) slot = v.get();
        if (!slot || !pool_names_.count(validator))
            return fail(403, "'" + validator + "' no es validador de esta ronda", true);
        if (validator == proposer_)
            return fail(403, "'" + validator + "' es el proponente: su firma ya respalda el bloque", true);
        int st = slot->state.load();
        if (!slot->abstain || st == PosVoted || st == PosAgainst || external_votes_.count(validator))
            return fail(409, "'" + validator + "' ya emitió su voto: el doble voto se rechaza", true);
        if (st == PosAbstained) return fail(409, "la ventana de votación de '" + validator + "' ya cerró", true);
        external_votes_[validator] = vote;
        status = 200;
        message = "voto '" + vote + "' de " + validator + " recibido";
        return true;
    }();
    // Written after releasing mu_: never touch the database while holding it.
    if (!log.empty()) ledger_.log_event("vote_rejected", log);
    return ok;
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
        std::vector<TxRow> txs = ledger_.mempool(cfg_.max_tx_per_block);
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
                publish_block({b, txs, {}, {}, 0});
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

    set_phase(result.value("outcome", "") == "sealed" ? "GANADOR" : "SIN_GANADOR");
    std::lock_guard<std::mutex> g(mu_);
    result_ = result;
    finished_ms_ = now_ms();
    running_ = false;
}

// ---------------------------------------------------------------- PoS ----------------------

void ConsensusCoordinator::cast_vote(VoterSlot* slot, std::string block_hash, std::string proposer_sig,
                                      std::string proposer_pubkey, int64_t window_deadline_ms) {
    slot->state = PosVoting;
    // An honest validator checks the proposal before voting: if the proposer's signature does
    // not verify (a dishonest proposal), it votes NO.
    if (!crypto::verify_p256(proposer_pubkey, block_hash, proposer_sig)) {
        slot->state = PosAgainst;
        return;
    }
    // Seeded per validator: with the same seed the same validators answer in the same order.
    std::mt19937_64 rng(seed_ ^ fnv1a(slot->node.name));
    std::uniform_int_distribution<int> delay_ms(50, 300);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms(rng)));

    bool vote_yes = !slot->abstain;
    if (slot->abstain) {
        // Simulated non-responsive validator: it stays silent unless an external vote arrives
        // before the voting window closes.
        while (!stop_.load() && now_ms() < window_deadline_ms) {
            {
                std::lock_guard<std::mutex> g(mu_);
                auto it = external_votes_.find(slot->node.name);
                if (it != external_votes_.end()) {
                    if (it->second == "no") {
                        slot->state = PosAgainst;
                        return;
                    }
                    vote_yes = true;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    if (stop_.load() || !vote_yes) {
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
    BetRelease release{ledger_};  // bets stay locked for the round, whatever happens
    json result = nullptr;
    int64_t bets_total = 0;
    std::string reward_note;
    try {
        BlockRow tip = ledger_.tip();
        std::vector<TxRow> txs = ledger_.mempool(cfg_.max_tx_per_block);
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
        for (auto& v : voters_) {
            pool.push_back(v.get());
            bets_total += v->bet;
        }
        phase_pause();  // APUESTAS: bets are placed and locked (done in start())

        int attempt = 0;
        while (!stop_.load()) {
            set_phase("SORTEO");
            std::vector<chain::StakeEntry> stake_snapshot;
            int64_t total = 0;
            for (auto* v : pool) {
                stake_snapshot.push_back({v->node.name, v->bet});  // the lottery weighs the BET
                total += v->bet;
            }
            if (pool.empty() || total <= 0) {
                set_phase("RECHAZADO");
                result = {{"outcome", "no_quorum"}, {"error", "se agotó el conjunto de validadores sin sellar el bloque"}};
                break;
            }
            {
                std::lock_guard<std::mutex> g(mu_);
                total_stake_ = total;
                quorum_threshold_ = chain::quorum_threshold(total);
                attempt_ = attempt;
                pool_names_.clear();
                for (auto* v : pool) pool_names_.insert(v->node.name);
            }
            phase_pause();

            std::string proposer_name = chain::select_proposer(stake_snapshot, tip.hash, height, attempt);
            VoterSlot* proposer_slot = nullptr;
            for (auto* v : pool)
                if (v->node.name == proposer_name) proposer_slot = v;
            {
                std::lock_guard<std::mutex> g(mu_);
                proposer_ = proposer_name;
            }
            if (!proposer_slot) {
                set_phase("RECHAZADO");
                result = {{"outcome", "error"}, {"error", "sorteo produjo un proponente desconocido"}};
                break;
            }

            set_phase("CANDIDATO");
            phase_pause();
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

            {
                std::lock_guard<std::mutex> g(mu_);
                for (auto* v : pool) {
                    v->state = PosIdle;
                    v->signature.clear();
                    v->voted_at_ms = 0;
                    v->abstain = false;
                }
                external_votes_.clear();
                std::vector<VoterSlot*> order(pool);
                std::stable_sort(order.begin(), order.end(), [](VoterSlot* a, VoterSlot* b) { return a->bet < b->bet; });
                int ab = std::min<int>(abstain_count, static_cast<int>(order.size()));
                for (int i = 0, done = 0; i < static_cast<int>(order.size()) && done < ab; ++i) {
                    if (order[i] == proposer_slot) continue;  // the proposer's own backing is not simulated away
                    order[i]->abstain = true;
                    ++done;
                }
            }

            set_phase("VOTACION");
            int64_t window_deadline = now_ms() + vote_window_ms_;
            std::vector<std::thread> threads;
            for (auto* v : pool)
                if (v != proposer_slot)
                    threads.emplace_back([this, v, block_hash, proposer_sig, pk = proposer_slot->node.public_key_spki,
                                          window_deadline] { cast_vote(v, block_hash, proposer_sig, pk, window_deadline); });
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
                                            {"stake", v->bet},
                                            {"vote", dishonest ? "dishonest_proposal" : "proposer"}});
                    // An honest proposer implicitly backs its own proposal: it counts toward
                    // quorum the same way any other "yes" vote does, so it must also appear in
                    // `votes` (using its existing block signature) -- otherwise check_block's
                    // recomputed sum of votes would never match `quorum`.
                    if (!dishonest) {
                        votes.push_back({v->node.id, v->node.name, proposer_sig, v->bet, ts});
                        quorum += v->bet;
                    }
                    continue;
                }
                int st = v->state.load();
                const char* label = st == PosVoted ? "yes" : st == PosAgainst ? "no" : "absent";
                participants.push_back({{"validator", v->node.name}, {"stake", v->bet}, {"vote", label}});
                if (st == PosVoted) {
                    votes.push_back({v->node.id, v->node.name, v->signature, v->bet, v->voted_at_ms});
                    quorum += v->bet;
                }
            }
            {
                std::lock_guard<std::mutex> g(mu_);
                quorum_stake_ = quorum;
            }

            int64_t duration = now_ms() - started_ms_;
            json round_log = {{"attempt", attempt},         {"proposer", proposer_name}, {"dishonest", dishonest},
                               {"quorum_stake", quorum},      {"total_stake", total}};

            if (quorum >= chain::quorum_threshold(total)) {
                BlockRow b;
                b.header = hdr;
                b.hash = block_hash;
                b.mode = "pos";
                b.proposer_signature = proposer_sig;
                b.quorum_stake = quorum;
                b.total_stake = total;
                b.tx_count = static_cast<int>(txs.size());
                json round = {{"participants", participants}, {"duration_ms", duration}};
                try {
                    ledger_.commit_block(b, txs, stake_snapshot, attempt, votes, round, cfg_.pos_reward);
                    publish_block({b, txs, votes, stake_snapshot, attempt});
                    round_log["outcome"] = "sealed";
                    set_phase("ACEPTADO");
                    reward_note = "Recompensa PoS: +" + std::to_string(cfg_.pos_reward) + " para " + proposer_name;
                    {
                        std::lock_guard<std::mutex> g(mu_);
                        attempts_log_.push_back(round_log);
                    }
                    result = {{"outcome", "sealed"},        {"proposer", proposer_name},
                              {"height", b.header.height},   {"hash", b.hash},
                              {"quorum_stake", quorum},       {"total_stake", total},
                              {"tx_count", b.tx_count},       {"attempts", attempt + 1},
                              {"reward", cfg_.pos_reward}};
                } catch (const std::exception& e) {
                    round_log["outcome"] = "rejected";
                    set_phase("RECHAZADO");
                    {
                        std::lock_guard<std::mutex> g(mu_);
                        attempts_log_.push_back(round_log);
                    }
                    result = {{"outcome", "rejected"}, {"proposer", proposer_name}, {"error", e.what()}};
                }
                break;
            }

            set_phase("RECHAZADO");
            if (!dishonest) {
                // A genuinely valid proposal simply didn't gather enough participation this
                // round (e.g. simulated abstentions) -- nothing to punish, the round just ends.
                round_log["outcome"] = "no_quorum";
                {
                    std::lock_guard<std::mutex> g(mu_);
                    attempts_log_.push_back(round_log);
                }
                result = {{"outcome", "no_quorum"},
                          {"error", "quórum no alcanzado: " + std::to_string(quorum) + "/" +
                                        std::to_string(chain::quorum_threshold(total)) + " (de " + std::to_string(total) + ")"}};
                break;
            }

            // Caught: the dishonest proposer is slashed and removed from the pool, then the
            // sorteo repeats with an incremented attempt ("intento") over the remainder.
            db_.exec(
                "INSERT INTO consensus_rounds (mode, attempt, proposer, participants, quorum_stake, total_stake, "
                "duration_ms, outcome) VALUES ('pos',$1,$2,$3,$4,$5,$6,'rejected_retry')",
                {attempt, proposer_name, participants.dump(), quorum, total, duration});
            round_log["outcome"] = "rejected_retry";
            {
                std::lock_guard<std::mutex> g(mu_);
                attempts_log_.push_back(round_log);
            }

            // c is taken from the proposer's BET a_p. Rule (A): c = a_p, and the node is barred
            // from future rounds. Rule (B): c = min(a_p, ceil(alpha * value of the block's
            // transactions)) with value = tx_count * TX_VALUE; the node stays eligible.
            bool bar = punishment_rule_ == "A";
            int64_t bet = proposer_slot->bet;
            int64_t tx_value_total = static_cast<int64_t>(txs.size()) * cfg_.tx_value;
            int64_t cut = bar ? bet
                              : std::min<int64_t>(bet, static_cast<int64_t>(std::ceil(alpha_ * static_cast<double>(tx_value_total))));
            json evidence = {{"block_hash", block_hash}, {"attempt", attempt}, {"punishment_rule", punishment_rule_},
                              {"bet", bet},               {"tx_value", tx_value_total}};
            ledger_.slash(proposer_slot->node.id, cut, bar, "dishonest_proposal", evidence,
                         std::optional<int64_t>(height));
            pool.erase(std::remove(pool.begin(), pool.end(), proposer_slot), pool.end());
            ++attempt;
        }
        if (result.is_null()) {
            set_phase("RECHAZADO");
            result = {{"outcome", "no_quorum"}, {"error", "round stopped"}};
        }
    } catch (const std::exception& e) {
        result = {{"outcome", "error"}, {"error", e.what()}};
    }

    // Bets are released here (BetRelease runs when this function returns); say so in the log.
    try {
        if (!reward_note.empty()) ledger_.log_event("reward", reward_note);
        ledger_.log_event("stake", "Ronda PoS #" + std::to_string(round_no_) + ": apuestas liberadas (total " +
                                       std::to_string(bets_total) + ")");
    } catch (...) {
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
              {"phase", phase_},
              {"phase_log", phase_log_},
              {"seed", std::to_string(seed_)},
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
        j["vote_window_ms"] = vote_window_ms_;
        json vs = json::array();
        for (auto& v : voters_) {
            int st = v->state.load();
            const char* status = st == PosVoting ? "voting" : st == PosVoted ? "voted" : st == PosAbstained ? "abstained"
                                 : st == PosAgainst ? "against" : "idle";
            vs.push_back({{"name", v->node.name},
                         {"stake", v->node.stake},
                         {"bet", v->bet},
                         {"in_pool", pool_names_.count(v->node.name) > 0},
                         {"simulated_absent", v->abstain},
                         {"dishonest", v->node.dishonest},
                         {"status", status},
                         {"signature", v->signature.empty() ? json(nullptr) : json(v->signature)}});
        }
        j["validators"] = vs;
    }
    return j;
}
