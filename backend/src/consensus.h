#pragma once
#include <nlohmann/json.hpp>

#include <atomic>
#include <memory>
#include <mutex>
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
//  - PoS: a stake-weighted lottery ("sorteo") deterministically picks a proposer from the
//    remaining eligible pool. If the proposer is flagged dishonest, it proposes a block with a
//    corrupted signature; honest validators vote it down, it is slashed and removed from the
//    pool, and the draw repeats with an incremented attempt counter ("intento") until a block
//    is accepted or the pool is exhausted.
class ConsensusCoordinator {
public:
    ConsensusCoordinator(Ledger& ledger, Db& db, NodeNetwork& network, int max_tx_per_block, int64_t initial_stake);
    ~ConsensusCoordinator();

    // `difficulty_hex_zeros` is used only for mode=="pow". `abstain_count` (voters that simply
    // don't respond this round, for quorum-boundary demos), `punishment_rule` ('A': the
    // dishonest proposer forfeits its whole stake and is barred from future rounds; 'B': it
    // only loses min(stake, alpha * tx_count) and stays eligible) and `alpha` (0 < alpha <= 1,
    // rule B only) are used only for mode=="pos".
    bool start(const std::string& mode, int node_count, int difficulty_hex_zeros, int abstain_count,
               const std::string& punishment_rule, double alpha, std::string& err);
    void stop();
    nlohmann::json snapshot();
    bool running() const { return running_.load(); }

private:
    enum PowState { PowIdle = 0, PowMining, PowWinner, PowLate, PowStale };
    enum PosState { PosIdle = 0, PosVoting, PosVoted, PosAbstained };

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
        std::atomic<int> state{PosIdle};
        bool abstain = false;
        std::string signature;
        int64_t voted_at_ms = 0;
    };

    void run_pow(int difficulty_hex_zeros);
    void mine(MinerSlot* slot, int miner_index, int n, chain::BlockHeader header, int difficulty_hex_zeros);

    void run_pos(int abstain_count);
    void cast_vote(VoterSlot* slot, std::string block_hash, std::string proposer_sig, std::string proposer_pubkey);

    Ledger& ledger_;
    Db& db_;
    NodeNetwork& network_;
    int max_tx_;
    int64_t initial_stake_;

    std::mutex mu_;  // guards everything below that is not atomic
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<bool> found_{false};  // PoW: set once any miner wins, to stop the rest
    std::atomic<bool> stop_{false};
    std::string mode_;
    std::string punishment_rule_ = "A";
    double alpha_ = 1.0;

    std::vector<std::unique_ptr<MinerSlot>> miners_;
    std::vector<std::unique_ptr<VoterSlot>> voters_;

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
