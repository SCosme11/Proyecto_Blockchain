#pragma once
#include <nlohmann/json.hpp>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "ledger.h"
#include "network.h"

// Runs one consensus round at a time, in either mode, sharing the same block/tx format and
// the same live-snapshot/SSE telemetry plumbing:
//
//  - PoW: all N nodes become miners and race over disjoint nonce residue classes (miner i
//    tries i, i+N, i+2N, ...) for a hash with `d` leading hex-zero digits. Smallest winning
//    nonce wins ties (well-defined: residues never collide). The winner's reward is pending
//    until the chain reaches height+6.
//  - PoS: a state machine APUESTAS -> SORTEO -> CANDIDATO -> VOTACION -> ACEPTADO/RECHAZADO.
//    Each validator bets 0 < a_i <= its stake (locked for the round); a stake-weighted lottery
//    over the bets deterministically picks a proposer; validators vote with weight a_i and the
//    block is accepted at >= 2/3 of the total bet. If the proposer is flagged dishonest it
//    proposes a block with a corrupted signature; honest validators vote it down, it is
//    slashed and removed from the pool, and the draw repeats with an incremented attempt
//    counter ("intento") until a block is accepted or the pool is exhausted.
struct ConsensusParams {
    std::string mode = "pos";         // "pow" | "pos"
    int node_count = 10;              // N, 10..20 (validated by the API)
    int difficulty_hex_zeros = 4;     // PoW only
    int abstain_count = 0;            // PoS: validators that don't answer by themselves
    std::string punishment_rule = "A";  // PoS: 'A' c = a_p ; 'B' c = min(a_p, alpha * tx value)
    double alpha = 1.0;               // rule B only, 0 < alpha <= 1
    int validators = 0;               // PoS: random subset size (0 = every node with stake)
    int bet_pct = 100;                // PoS: default bet = bet_pct % of each validator's stake
    std::map<std::string, int64_t> bets;  // PoS: explicit per-validator bets (override bet_pct)
    int vote_window_ms = 0;           // PoS: extra time the voting stays open for external votes
    bool has_seed = false;
    uint64_t seed = 0;                // reproducible randomness (subset, vote delays)
};

class ConsensusCoordinator {
public:
    struct Config {
        int max_tx_per_block = 10;
        int64_t initial_stake = 100;
        int64_t tx_value = 10;      // "valor" of one transaction, used by punishment rule B
        int64_t pos_reward = 5;     // credited to the proposer of an accepted PoS block
        int phase_delay_ms = 250;   // pause on APUESTAS/SORTEO/CANDIDATO so the UI can show them
        uint64_t default_seed = 0;  // 0 = pick a fresh seed per round
    };

    ConsensusCoordinator(Ledger& ledger, Db& db, NodeNetwork& network, Config cfg);
    ~ConsensusCoordinator();

    // Returns false with `err` set; `status` is 400 for a bad parameter and 409 when the
    // current state of the system doesn't allow the round.
    bool start(const ConsensusParams& p, std::string& err, int& status);
    void stop();
    nlohmann::json snapshot();
    bool running() const { return running_.load(); }

    // External vote on behalf of a validator (PoS, during VOTACION). Only validators that were
    // simulated as non-responsive can still vote; anything else is rejected with a clear
    // message. `status` is the HTTP status to answer with.
    bool submit_vote(const std::string& validator, const std::string& vote, std::string& message, int& status);

private:
    enum PowState { PowIdle = 0, PowMining, PowWinner, PowLate, PowStale };
    enum PosState { PosIdle = 0, PosVoting, PosVoted, PosAbstained, PosAgainst };

    struct MinerSlot {
        NodeRow node;
        std::atomic<uint64_t> nonce{0};
        std::atomic<uint64_t> attempts{0};
        std::atomic<int> state{PowIdle};
        std::mutex hash_mu;
        std::string last_hash;
        uint64_t winning_nonce = 0;
    };

    struct VoterSlot {
        NodeRow node;
        int64_t bet = 0;  // a_i: the stake wagered (and locked) in this round
        std::atomic<int> state{PosIdle};
        bool abstain = false;
        std::string signature;
        int64_t voted_at_ms = 0;
    };

    void run_pow(int difficulty_hex_zeros);
    void mine(MinerSlot* slot, int miner_index, int n, chain::BlockHeader header, int difficulty_hex_zeros);

    void run_pos(int abstain_count);
    void cast_vote(VoterSlot* slot, std::string block_hash, std::string proposer_sig, std::string proposer_pubkey,
                   int64_t window_deadline_ms);
    void set_phase(const std::string& phase);
    void phase_pause();
    void publish_block(const ChainBlock& cb);

    Ledger& ledger_;
    Db& db_;
    NodeNetwork& network_;
    Config cfg_;

    std::mutex mu_;  // guards everything below that is not atomic
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<bool> found_{false};  // PoW: set once any miner wins, to stop the rest
    std::atomic<bool> stop_{false};
    std::string mode_;
    std::string punishment_rule_ = "A";
    double alpha_ = 1.0;
    int vote_window_ms_ = 0;
    uint64_t seed_ = 0;
    uint64_t round_counter_seed_ = 1;

    std::vector<std::unique_ptr<MinerSlot>> miners_;
    std::vector<std::unique_ptr<VoterSlot>> voters_;
    std::set<std::string> pool_names_;  // validators still eligible in the current attempt
    std::map<std::string, std::string> external_votes_;

    std::string phase_;
    nlohmann::json phase_log_ = nlohmann::json::array();
    std::string proposer_;
    int attempt_ = 0;
    int64_t total_stake_ = 0;
    int64_t quorum_threshold_ = 0;
    int64_t quorum_stake_ = 0;
    int64_t round_no_ = 0;
    int64_t started_ms_ = 0;
    int64_t finished_ms_ = 0;
    int64_t height_ = 0;
    std::string prev_hash_;
    std::vector<std::string> tx_ids_;
    nlohmann::json result_;
    nlohmann::json attempts_log_;  // PoS: history of this round's sorteo/reject/redraw attempts
};

int64_t now_ms();
