#include "chain.h"

#include <map>
#include <set>
#include <sstream>

#include "crypto.h"

namespace chain {

const char* kTxVersion = "v1";
const char* kZeroHash = "0000000000000000000000000000000000000000000000000000000000000000";

std::string canonical(const TxFields& f) {
    std::ostringstream o;
    o << kTxVersion << '|' << f.work_item_id << '|' << f.work_hash << '|' << f.artifact_type << '|'
      << f.score << '|' << f.rules_hash << '|' << f.decision << '|' << f.comment_hash << '|'
      << f.auditor_fpr << '|' << f.timestamp_ms;
    return o.str();
}

bool parse_canonical(const std::string& s, TxFields& out) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : s) {
        if (c == '|') {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    parts.push_back(cur);
    if (parts.size() != 10 || parts[0] != kTxVersion) return false;
    try {
        out.work_item_id = std::stoll(parts[1]);
        out.work_hash = parts[2];
        out.artifact_type = parts[3];
        out.score = parts[4];
        out.rules_hash = parts[5];
        out.decision = parts[6];
        out.comment_hash = parts[7];
        out.auditor_fpr = parts[8];
        out.timestamp_ms = std::stoll(parts[9]);
    } catch (...) {
        return false;
    }
    return true;
}

std::string tx_id(const std::string& canonical, const std::string& sig_hex) {
    return crypto::sha256_hex(canonical + "|" + sig_hex);
}

std::string merkle_root(const std::vector<std::string>& leaf_hex) {
    if (leaf_hex.empty()) return kZeroHash;
    std::vector<crypto::Bytes> level;
    for (const auto& h : leaf_hex) {
        crypto::Bytes b;
        crypto::from_hex(h, b);
        level.push_back(b);
    }
    while (level.size() > 1) {
        if (level.size() % 2) level.push_back(level.back());
        std::vector<crypto::Bytes> next;
        for (size_t i = 0; i < level.size(); i += 2) {
            crypto::Bytes cat = level[i];
            cat.insert(cat.end(), level[i + 1].begin(), level[i + 1].end());
            next.push_back(crypto::sha256d(cat.data(), cat.size()));
        }
        level.swap(next);
    }
    return crypto::to_hex(level[0]);
}

std::string canonical_header(const BlockHeader& h) {
    std::ostringstream o;
    o << "v1|" << h.height << '|' << h.prev_hash << '|' << h.merkle_root << '|' << h.timestamp_ms << '|'
      << h.proposer << '|' << h.nonce << '|' << h.difficulty_hex_zeros;
    return o.str();
}

std::string block_hash(const BlockHeader& h) {
    std::string data = canonical_header(h);
    return crypto::to_hex(crypto::sha256d(data.data(), data.size()));
}

bool meets_difficulty(const std::string& hash_hex, int hex_zeros) {
    if (hex_zeros <= 0) return true;
    if (static_cast<int>(hash_hex.size()) < hex_zeros) return false;
    return hash_hex.compare(0, hex_zeros, std::string(hex_zeros, '0')) == 0;
}

BlockHeader genesis_header() {
    BlockHeader g;
    g.height = 0;
    g.prev_hash = kZeroHash;
    g.merkle_root = kZeroHash;
    g.timestamp_ms = 1767225600000;  // 2026-01-01T00:00:00Z
    g.proposer = "genesis";
    return g;
}

std::string select_proposer(const std::vector<StakeEntry>& stakes, const std::string& prev_hash, int64_t height,
                            int attempt) {
    int64_t total = 0;
    for (const auto& s : stakes) total += s.stake;
    if (stakes.empty() || total <= 0) return "";

    std::ostringstream seed_in;
    seed_in << prev_hash << '|' << height << '|' << attempt;
    std::string seed_str = seed_in.str();
    crypto::Bytes digest = crypto::sha256(seed_str.data(), seed_str.size());
    uint64_t seed = 0;
    for (int i = 0; i < 8; ++i) seed = (seed << 8) | digest[i];
    uint64_t point = seed % static_cast<uint64_t>(total);

    int64_t acc = 0;
    for (const auto& s : stakes) {
        acc += s.stake;
        if (point < static_cast<uint64_t>(acc)) return s.name;
    }
    return stakes.back().name;  // rounding fallback, should not be reached
}

int64_t quorum_threshold(int64_t total_stake) {
    // ceil(2 * total / 3) without floating point.
    return (2 * total_stake + 2) / 3;
}

std::vector<std::string> check_vote_set(const std::vector<StakeEntry>& snapshot, const std::vector<VoteStake>& votes,
                                        int64_t total_stake, int64_t quorum_stake) {
    std::vector<std::string> errs;
    std::map<std::string, int64_t> table;
    int64_t snapshot_total = 0;
    for (const auto& e : snapshot) {
        table[e.name] = e.stake;
        snapshot_total += e.stake;
    }
    if (total_stake != snapshot_total)
        errs.push_back("total_stake " + std::to_string(total_stake) + " does not match the round's stake snapshot (" +
                       std::to_string(snapshot_total) + ")");

    std::set<std::string> seen;
    int64_t sum = 0;
    for (const auto& v : votes) {
        auto it = table.find(v.name);
        if (it == table.end()) {
            errs.push_back("vote from '" + v.name + "', who is not a validator of this round");
        } else if (v.stake != it->second) {
            errs.push_back("vote of '" + v.name + "' claims stake " + std::to_string(v.stake) +
                           " but the round snapshot says " + std::to_string(it->second));
        }
        if (!seen.insert(v.name).second) errs.push_back("'" + v.name + "' voted more than once");
        sum += v.stake;
    }
    if (sum != quorum_stake) errs.push_back("quorum_stake does not match the sum of recorded votes");
    if (quorum_stake < quorum_threshold(total_stake))
        errs.push_back("quorum not reached: " + std::to_string(quorum_stake) + "/" + std::to_string(total_stake) +
                       " stake signed");
    return errs;
}

}  // namespace chain
