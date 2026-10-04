#pragma once
#include <nlohmann/json.hpp>

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ledger.h"

// Simulates each node keeping its OWN copy of the chain (in memory; no real P2P). Every
// sealed block is "broadcast" to every node's mirror; each mirror independently checks that
// the new block actually links onto what it already has before adopting it -- exactly the
// chain-acceptance rule in the guide, minus re-running the full consensus/signature check
// (already done once, authoritatively, by Ledger::commit_block before a block can exist at
// all). A mirror that is corrupted by the tamper demo stops accepting new blocks until it is
// explicitly resynced, which is how the "rejects an invalid/shorter chain" cases are shown.
class NodeNetwork {
public:
    struct Mirror {
        int node_id = 0;
        std::string name;
        int64_t height = 0;
        std::string hash;
        bool out_of_sync = false;
        std::string note;
    };

    // Makes sure every currently-registered node has a mirror, seeding new ones at the
    // reference chain's current tip (a new node is modelled as having just finished an
    // initial sync, not as replaying history from genesis).
    void sync_registry(const std::vector<NodeRow>& nodes, int64_t ref_height, const std::string& ref_hash);

    // Offers a newly-sealed block to every mirror. Each mirror independently re-runs the full
    // block check (`Ledger::check_block`) against ITS OWN stored tip as the expected
    // predecessor -- recomputing the hash, the consensus rule (PoW difficulty or PoS
    // proposer-selection + quorum + signatures) and every transaction's signature -- and only
    // adopts the block if that comes back clean. A mirror whose own copy was tampered with (or
    // that is simply missing an earlier block) fails the link check and falls behind.
    void broadcast(Ledger& ledger, const BlockRow& b, const std::vector<TxRow>& txs,
                   const std::map<std::string, std::string>& node_keys,
                   const std::vector<chain::StakeEntry>& stake_snapshot, int attempt,
                   const std::vector<VoteRow>& votes);

    // Demo-only: corrupts one node's stored tip hash, so the next broadcast is rejected.
    bool tamper(int node_id, std::string& err);

    // Demo-only: snaps one node's mirror back to the reference tip.
    bool resync(int node_id, int64_t ref_height, const std::string& ref_hash, std::string& err);

    nlohmann::json status(int64_t ref_height, const std::string& ref_hash);

    // Demo reset: drops every mirror so the next round reseeds them at the (now reset) tip.
    void reset();

private:
    std::mutex mu_;
    std::map<int, Mirror> mirrors_;
};
