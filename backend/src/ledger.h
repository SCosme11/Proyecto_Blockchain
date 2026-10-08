#pragma once
#include <nlohmann/json.hpp>

#include <map>
#include <mutex>
#include <optional>
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

struct NodeRow {
    int id = 0;
    std::string name;
    std::string public_key_spki;
    std::string private_key_pem;
    int64_t stake = 0;
    bool active = true;
    bool slashed = false;
    bool dishonest = false;
    int64_t balance = 0;  // credited rewards
    int64_t locked = 0;   // part of `stake` bet in the round currently running
};

struct VoteRow {
    int validator_id = 0;
    std::string validator_name;
    std::string signature;
    int64_t stake_at_vote = 0;
    int64_t voted_at_ms = 0;
};

struct BlockRow {
    chain::BlockHeader header;
    std::string hash;
    std::string mode = "pos";  // "pow" | "pos"
    std::string proposer_signature;
    int64_t quorum_stake = 0;  // PoS only
    int64_t total_stake = 0;   // PoS only
    int tx_count = 0;
};

struct RewardRow {
    int64_t height = 0;
    int miner_id = 0;
    std::string miner_name;
    bool confirmed = false;
    int64_t amount = 0;
};

// A block together with everything needed to re-validate it in isolation. A node's own copy of
// the chain is a vector of these (see network.h).
struct ChainBlock {
    BlockRow block;
    std::vector<TxRow> txs;
    std::vector<VoteRow> votes;
    std::vector<chain::StakeEntry> snapshot;  // PoS: stake table frozen at round time
    int attempt = 0;
};

class Ledger {
public:
    explicit Ledger(Db& db) : db_(db) {}

    void apply_schema(const std::string& path);
    void ensure_genesis();

    BlockRow tip();
    std::vector<TxRow> mempool(int limit);
    std::vector<NodeRow> ensure_nodes(int n, int64_t initial_stake);
    std::vector<NodeRow> nodes();
    std::map<std::string, std::string> node_keys();
    int64_t total_active_stake();

    // Adjusts a node's stake by `delta` (negative to unstake). Rejects (returns false,
    // sets err) if the node is slashed or the result would be negative.
    bool adjust_stake(int node_id, int64_t delta, std::string& err);

    // Toggles the "propose a dishonest/invalid block when sorteed" demo flag.
    bool set_dishonest(int node_id, bool dishonest, std::string& err);

    // Penalizes a node for `reason`, cutting its stake by `amount` (capped at its current
    // stake) and recording the event in `slashing_events` for the audit log. If `bar` is set
    // the node is also marked permanently `slashed`/inactive (punishment rule A, full
    // forfeiture); if not, it keeps `active=true` and can be drawn again in later rounds, only
    // lighter in stake (punishment rule B, partial forfeiture).
    void slash(int node_id, int64_t amount, bool bar, const std::string& reason,
               const nlohmann::json& evidence, std::optional<int64_t> block_height);

    // Validates one block against its predecessor, its transactions and the node registry.
    // `stake_snapshot`/`attempt` are the PoS sortition context used to pick the proposer for
    // this block (frozen at round start, not necessarily today's `nodes` table); unused for
    // PoW blocks (pass {} / 0). Returns a list of human-readable problems (empty == valid).
    std::vector<std::string> check_block(const BlockRow& b, const std::string& expected_prev,
                                         const std::vector<TxRow>& txs,
                                         const std::map<std::string, std::string>& node_keys,
                                         const std::vector<chain::StakeEntry>& stake_snapshot, int attempt,
                                         const std::vector<VoteRow>& votes,
                                         bool check_artifacts);

    // Atomically appends a block (validated first) plus its votes/round record and, for PoW
    // blocks, a pending reward entry. PoS blocks credit `proposer_reward` to the proposer's
    // balance immediately. Throws on rejection.
    void commit_block(const BlockRow& b, const std::vector<TxRow>& txs,
                       const std::vector<chain::StakeEntry>& stake_snapshot, int attempt,
                       const std::vector<VoteRow>& votes, const nlohmann::json& round,
                       int64_t proposer_reward = 0);

    // Reward paid per PoW block once it matures (6 confirmations).
    int64_t block_reward = 10;

    // Snapshot of the whole reference chain (blocks + txs + votes + stake snapshots), the
    // thing a node would send a peer. Takes the DB lock.
    std::vector<ChainBlock> export_chain();

    // Validates a whole chain from genesis and returns the same JSON shape as verify_chain().
    // `check_artifacts` additionally re-hashes the off-chain artifacts (needs the DB).
    nlohmann::json validate_chain(const std::vector<ChainBlock>& chain,
                                  const std::map<std::string, std::string>& node_keys, bool check_artifacts);

    // Reward status for one block height (nullopt if that block has no PoW reward).
    std::optional<RewardRow> reward(int64_t height);
    int64_t tip_height();

    // Bets (PoS): lock/release the part of each node's stake wagered in the running round.
    void lock_bets(const std::map<int, int64_t>& bets);
    void release_all_locks();

    // Appends to the human-readable audit log shown in the UI.
    void log_event(const std::string& type, const std::string& message);

    // Reward bookkeeping (PoW): rewards for the miner of `height` mature once the chain
    // reaches height+6. Called automatically after every commit.
    std::vector<RewardRow> rewards();

    // Re-verifies the entire chain from genesis, including off-chain artifacts.
    nlohmann::json verify_chain();

    // Serialises consensus rounds and block commits.
    std::mutex chain_mu;

private:
    std::vector<TxRow> block_txs(int64_t height);
    std::vector<VoteRow> block_votes(int64_t height);
    std::vector<chain::StakeEntry> round_stake_snapshot(int64_t block_height);
    int round_attempt(int64_t block_height);
    void mature_pow_rewards(int64_t current_height);
    Db& db_;
};

BlockRow block_from_result(const Result& r, int row);
