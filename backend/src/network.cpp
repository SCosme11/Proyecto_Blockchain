#include "network.h"

using nlohmann::json;

void NodeNetwork::sync_registry(const std::vector<NodeRow>& nodes, int64_t ref_height, const std::string& ref_hash) {
    std::lock_guard<std::mutex> g(mu_);
    for (const auto& n : nodes) {
        auto it = mirrors_.find(n.id);
        if (it == mirrors_.end()) {
            Mirror m;
            m.node_id = n.id;
            m.name = n.name;
            m.height = ref_height;
            m.hash = ref_hash;
            mirrors_[n.id] = m;
        } else {
            it->second.name = n.name;  // keep display name current
        }
    }
}

void NodeNetwork::broadcast(Ledger& ledger, const BlockRow& b, const std::vector<TxRow>& txs,
                            const std::map<std::string, std::string>& node_keys,
                            const std::vector<chain::StakeEntry>& stake_snapshot, int attempt,
                            const std::vector<VoteRow>& votes) {
    std::lock_guard<std::mutex> g(mu_);
    for (auto& [id, m] : mirrors_) {
        if (m.out_of_sync) continue;  // stays behind until explicitly resynced
        // Each node checks the block against ITS OWN tip, independently: hash recomputation,
        // the PoW/PoS consensus rule, every signature and the merkle root -- the same full
        // check the reference ledger itself ran, just re-run from this node's point of view.
        auto errs = ledger.check_block(b, m.hash, txs, node_keys, stake_snapshot, attempt, votes, false);
        if (errs.empty()) {
            m.height = b.header.height;
            m.hash = b.hash;
            m.note.clear();
        } else {
            m.out_of_sync = true;
            m.note = errs.front();
        }
    }
}

bool NodeNetwork::tamper(int node_id, std::string& err) {
    std::lock_guard<std::mutex> g(mu_);
    auto it = mirrors_.find(node_id);
    if (it == mirrors_.end()) {
        err = "node has no chain copy yet";
        return false;
    }
    std::string& h = it->second.hash;
    if (!h.empty()) h[0] = (h[0] == 'f') ? '0' : 'f';  // flip one hex digit of its stored tip hash
    it->second.out_of_sync = true;
    it->second.note = "local copy corrupted by the tamper demo";
    return true;
}

bool NodeNetwork::resync(int node_id, int64_t ref_height, const std::string& ref_hash, std::string& err) {
    std::lock_guard<std::mutex> g(mu_);
    auto it = mirrors_.find(node_id);
    if (it == mirrors_.end()) {
        err = "node has no chain copy yet";
        return false;
    }
    it->second.height = ref_height;
    it->second.hash = ref_hash;
    it->second.out_of_sync = false;
    it->second.note.clear();
    return true;
}

void NodeNetwork::reset() {
    std::lock_guard<std::mutex> g(mu_);
    mirrors_.clear();
}

json NodeNetwork::status(int64_t ref_height, const std::string& ref_hash) {
    std::lock_guard<std::mutex> g(mu_);
    json arr = json::array();
    for (auto& [id, m] : mirrors_) {
        bool synced = !m.out_of_sync && m.height == ref_height && m.hash == ref_hash;
        arr.push_back({{"node_id", m.node_id},
                       {"name", m.name},
                       {"height", m.height},
                       {"hash", m.hash},
                       {"synced", synced},
                       {"note", m.note.empty() ? json(nullptr) : json(m.note)}});
    }
    return arr;
}
