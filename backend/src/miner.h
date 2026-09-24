#pragma once
#include <nlohmann/json.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ledger.h"

// Permissioned proof-of-work: N registered miners (one thread each) race to seal the next block.
// Each miner builds its own candidate (its name is in the header, like a coinbase), so they search
// disjoint hash spaces. The first valid PoW wins, signs the block with its key, and the ledger
// validates and appends it; the other candidates become stale.
class MiningCoordinator {
public:
    MiningCoordinator(Ledger& ledger, Db& db, int max_tx_per_block);
    ~MiningCoordinator();

    bool start(int miner_count, int difficulty_bits, std::string& err);
    void stop();
    nlohmann::json snapshot();
    bool running() const { return running_.load(); }

private:
    enum State { Idle = 0, Mining, Winner, Late, Stale };

    struct Slot {
        MinerRow miner;
        std::atomic<uint64_t> hashes{0};
        std::atomic<int> state{Idle};
        uint64_t nonce = 0;
        std::string hash;
        int64_t found_at_ms = 0;
    };

    void run_round(int difficulty_bits);
    void mine(size_t idx, const chain::BlockHeader& header);

    Ledger& ledger_;
    Db& db_;
    int max_tx_;

    std::mutex mu_;  // guards everything below that is not atomic
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<bool> found_{false};
    std::atomic<bool> stop_{false};
    std::vector<std::unique_ptr<Slot>> slots_;
    int winner_ = -1;
    int64_t round_no_ = 0;
    int64_t started_ms_ = 0;
    int64_t finished_ms_ = 0;
    int difficulty_ = 0;
    int64_t height_ = 0;
    std::string prev_hash_;
    std::vector<std::string> tx_ids_;
    nlohmann::json result_;
};

int64_t now_ms();
