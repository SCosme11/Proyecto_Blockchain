#pragma once
#include <nlohmann/json.hpp>

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "chain.h"
#include "db.h"

// Chain state on top of Postgres: genesis, tip, mempool selection, block commit and full validation.
struct TxRow {
    std::string tx_id;
    std::string canonical;
    std::string signature;
    std::string comment;
    std::string auditor_spki;
    std::string auditor_name;
    int64_t work_item_id = 0;
};

struct MinerRow {
    int id = 0;
    std::string name;
    std::string public_key_spki;
    std::string private_key_pem;
};

struct BlockRow {
    chain::BlockHeader header;
    std::string hash;
    std::string miner_signature;
    int tx_count = 0;
};

class Ledger {
public:
    explicit Ledger(Db& db) : db_(db) {}

    void apply_schema(const std::string& path);
    void ensure_genesis();

    BlockRow tip();
    std::vector<TxRow> mempool(int limit);
    std::vector<MinerRow> ensure_miners(int n);
    std::map<std::string, std::string> miner_keys();

    // Validates one block against its predecessor, its transactions and the miner registry.
    // Returns a list of human-readable problems (empty == valid).
    std::vector<std::string> check_block(const BlockRow& b, const std::string& expected_prev,
                                         const std::vector<TxRow>& txs,
                                         const std::map<std::string, std::string>& miner_keys,
                                         bool check_artifacts);

    // Atomically appends a block (validated first). Throws on rejection.
    void commit_block(const BlockRow& b, const std::vector<TxRow>& txs, const nlohmann::json& round);

    // Re-verifies the entire chain from genesis, including off-chain artifacts.
    nlohmann::json verify_chain();

    // Serialises block commits and mining rounds.
    std::mutex chain_mu;

private:
    std::vector<TxRow> block_txs(int64_t height);
    Db& db_;
};

BlockRow block_from_result(const Result& r, int row);
