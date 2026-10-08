#include "network.h"

using nlohmann::json;

namespace {

// First error of the first bad block, or "" if the validation report is clean.
std::string first_error(const json& report) {
    if (report.value("ok", false)) return "";
    for (const auto& b : report["blocks"])
        if (!b["ok"].get<bool>()) return "block #" + std::to_string(b["height"].get<int64_t>()) + ": " + b["errors"][0].get<std::string>();
    return "invalid chain";
}

}  // namespace

void NodeNetwork::revalidate(Ledger& ledger, Mirror& m, const std::map<std::string, std::string>& node_keys) {
    json report = ledger.validate_chain(m.chain, node_keys, false);
    m.valid = report.value("ok", false);
    m.invalid_height = m.valid ? -1 : report["first_bad_height"].get<int64_t>();
    m.invalid_reason = m.valid ? "" : first_error(report);
}

void NodeNetwork::sync_registry(Ledger& ledger, const std::vector<NodeRow>& nodes) {
    std::vector<const NodeRow*> missing;
    {
        std::lock_guard<std::mutex> g(mu_);
        for (const auto& n : nodes) {
            auto it = mirrors_.find(n.id);
            if (it == mirrors_.end()) missing.push_back(&n);
            else it->second.name = n.name;  // keep display name current
        }
    }
    if (missing.empty()) return;
    std::vector<ChainBlock> reference = ledger.export_chain();  // DB access happens outside mu_
    json report = ledger.validate_chain(reference, ledger.node_keys(), false);
    std::lock_guard<std::mutex> g(mu_);
    for (const NodeRow* n : missing) {
        if (mirrors_.count(n->id)) continue;
        Mirror m;
        m.node_id = n->id;
        m.name = n->name;
        m.chain = reference;
        m.valid = report.value("ok", false);
        if (!m.valid) {
            m.invalid_height = report["first_bad_height"].get<int64_t>();
            m.invalid_reason = first_error(report);
        }
        mirrors_[n->id] = std::move(m);
    }
}

std::vector<std::string> NodeNetwork::broadcast(Ledger& ledger, const ChainBlock& cb,
                                                const std::map<std::string, std::string>& node_keys) {
    std::vector<std::string> refusals;
    std::lock_guard<std::mutex> g(mu_);
    for (auto& [id, m] : mirrors_) {
        std::string who = m.name;
        if (m.out_of_sync) {
            // Stays behind until it receives a valid longer chain; say so in the log.
            refusals.push_back(who + " no recibió el bloque #" + std::to_string(cb.block.header.height) +
                               ": sigue desincronizado (" + m.note + ")");
            continue;
        }
        if (!m.valid) {
            m.out_of_sync = true;
            m.note = "own chain is invalid (" + m.invalid_reason + "); refusing new blocks";
            refusals.push_back(who + " rechazó el bloque #" + std::to_string(cb.block.header.height) + ": " + m.note);
            continue;
        }
        const std::string expected_prev = m.chain.empty() ? "" : m.chain.back().block.hash;
        // Each node checks the block against ITS OWN tip, independently: hash recomputation,
        // the PoW/PoS consensus rule, every signature and the merkle root.
        auto errs = ledger.check_block(cb.block, expected_prev, cb.txs, node_keys, cb.snapshot, cb.attempt, cb.votes,
                                       false);
        int64_t expected_height = m.chain.empty() ? 0 : m.chain.back().block.header.height + 1;
        if (cb.block.header.height != expected_height)
            errs.push_back("block #" + std::to_string(cb.block.header.height) + " does not follow own height " +
                           std::to_string(expected_height - 1));
        if (errs.empty()) {
            m.chain.push_back(cb);
            m.note.clear();
        } else {
            m.out_of_sync = true;
            m.note = errs.front();
            refusals.push_back(who + " rechazó el bloque #" + std::to_string(cb.block.header.height) + ": " + errs.front());
        }
    }
    return refusals;
}

NodeNetwork::Outcome NodeNetwork::receive_chain(Ledger& ledger, int node_id, const std::vector<ChainBlock>& candidate,
                                                const std::map<std::string, std::string>& node_keys) {
    std::lock_guard<std::mutex> g(mu_);
    auto it = mirrors_.find(node_id);
    if (it == mirrors_.end()) return {false, "node has no chain copy yet"};
    Mirror& m = it->second;

    if (candidate.empty()) return {false, "received chain is empty"};
    // (a)-(c): every block of the candidate must validate, starting from genesis.
    json report = ledger.validate_chain(candidate, node_keys, false);
    if (!report.value("ok", false)) return {false, "received chain is invalid -- " + first_error(report)};
    if (!m.chain.empty() && candidate.front().block.hash != m.chain.front().block.hash)
        return {false, "received chain has a different genesis block"};

    // (d): it must also be longer than ours -- unless ours is broken, in which case any valid
    // chain of at least the same length is an improvement.
    size_t own = m.chain.size();
    if (m.valid && candidate.size() <= own) {
        bool same_tip = candidate.size() == own && candidate.back().block.hash == m.chain.back().block.hash;
        if (same_tip) {
            m.out_of_sync = false;
            m.note.clear();
            return {true, "already up to date"};
        }
        return {false, "received chain is valid but not longer than the node's own (" + std::to_string(candidate.size()) +
                           " vs " + std::to_string(own) + " blocks)"};
    }
    if (!m.valid && candidate.size() < own)
        return {false, "received chain is shorter than the node's own (" + std::to_string(candidate.size()) + " vs " +
                           std::to_string(own) + " blocks)"};

    m.chain = candidate;
    m.valid = true;
    m.invalid_height = -1;
    m.invalid_reason.clear();
    m.out_of_sync = false;
    m.note.clear();
    return {true, "adopted a valid chain of " + std::to_string(candidate.size()) + " blocks"};
}

bool NodeNetwork::tamper(Ledger& ledger, int node_id, const std::map<std::string, std::string>& node_keys,
                         std::string& err, int* tampered_node, int64_t* tampered_height) {
    std::lock_guard<std::mutex> g(mu_);
    if (mirrors_.empty()) {
        err = "no node has a chain copy yet: run a consensus round first";
        return false;
    }
    auto it = node_id < 0 ? mirrors_.begin() : mirrors_.find(node_id);
    if (it == mirrors_.end()) {
        err = "node has no chain copy yet";
        return false;
    }
    Mirror& m = it->second;
    if (m.chain.size() < 2) {
        err = "seal at least one block first (the node's copy only holds genesis)";
        return false;
    }
    // Corrupt a block in the MIDDLE of the copy: everything after it must be rejected too.
    size_t idx = std::max<size_t>(1, m.chain.size() / 2);
    std::string& h = m.chain[idx].block.hash;
    h[0] = (h[0] == 'f') ? '0' : 'f';
    revalidate(ledger, m, node_keys);
    m.out_of_sync = true;
    m.note = "local copy corrupted at block #" + std::to_string(idx);
    if (tampered_node) *tampered_node = m.node_id;
    if (tampered_height) *tampered_height = static_cast<int64_t>(idx);
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
        int64_t height = m.chain.empty() ? 0 : m.chain.back().block.header.height;
        std::string hash = m.chain.empty() ? "" : m.chain.back().block.hash;
        bool synced = !m.out_of_sync && m.valid && height == ref_height && hash == ref_hash;
        std::string note = !m.note.empty() ? m.note : (!m.valid ? "own chain invalid: " + m.invalid_reason : "");
        arr.push_back({{"node_id", m.node_id},
                       {"name", m.name},
                       {"height", height},
                       {"hash", hash},
                       {"chain_length", m.chain.size()},
                       {"valid", m.valid},
                       {"synced", synced},
                       {"note", note.empty() ? json(nullptr) : json(note)}});
    }
    return arr;
}
