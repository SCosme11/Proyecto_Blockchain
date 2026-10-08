#pragma once
#include <nlohmann/json.hpp>

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ledger.h"

// Simulates each node keeping its OWN full copy of the chain (in memory; no real P2P), with
// the acceptance rules of the guide (section 2.4):
//
//  * A block broadcast by the proposer is only appended if the node's own chain is still valid
//    AND the block passes the full `Ledger::check_block` (hash, consensus rule, every
//    signature, merkle root) against the node's own tip.
//  * A whole chain received from a peer is adopted only if EVERY block validates from genesis
//    and it is longer than the node's own chain (or the node's own chain is itself invalid,
//    which is the only way a same-length chain can be an improvement). Otherwise the node
//    rejects it and keeps its own.
//
// Nothing here talks to the database while holding `mu_`: callers fetch the reference chain
// first and pass it in (this keeps the lock order simple: db lock -> mu_ is never inverted).
class NodeNetwork {
public:
    struct Mirror {
        int node_id = 0;
        std::string name;
        std::vector<ChainBlock> chain;
        bool valid = true;           // does the node's own copy validate from genesis?
        int64_t invalid_height = -1;  // first bad block when !valid
        std::string invalid_reason;
        bool out_of_sync = false;    // refused a block or was tampered; needs a chain from a peer
        std::string note;
    };

    struct Outcome {
        bool accepted = false;
        std::string reason;
    };

    // Makes sure every currently-registered node has a mirror. A node seen for the first time
    // is modelled as having just finished an initial sync (it receives a copy of the full
    // reference chain), not as replaying history itself.
    void sync_registry(Ledger& ledger, const std::vector<NodeRow>& nodes);

    // Offers a newly-sealed block to every mirror. Returns one log line per node that refused
    // it (the caller writes them to the event log after releasing every lock).
    std::vector<std::string> broadcast(Ledger& ledger, const ChainBlock& cb,
                                       const std::map<std::string, std::string>& node_keys);

    // A peer sends `candidate` to one node. Validates the WHOLE candidate and applies the
    // longest-valid-chain rule described above.
    Outcome receive_chain(Ledger& ledger, int node_id, const std::vector<ChainBlock>& candidate,
                          const std::map<std::string, std::string>& node_keys);

    // Demo-only: corrupts one block in the MIDDLE of a node's own copy (not just its tip).
    // `node_id` < 0 picks the first node.
    bool tamper(Ledger& ledger, int node_id, const std::map<std::string, std::string>& node_keys, std::string& err,
                int* tampered_node = nullptr, int64_t* tampered_height = nullptr);

    nlohmann::json status(int64_t ref_height, const std::string& ref_hash);

    // Demo reset: drops every mirror so the next round reseeds them from the (now reset) chain.
    void reset();

private:
    void revalidate(Ledger& ledger, Mirror& m, const std::map<std::string, std::string>& node_keys);

    std::mutex mu_;
    std::map<int, Mirror> mirrors_;
};
