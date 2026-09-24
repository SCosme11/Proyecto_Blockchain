#include "chain.h"

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

std::string header_prefix(const BlockHeader& h) {
    std::ostringstream o;
    o << "v1|" << h.height << '|' << h.prev_hash << '|' << h.merkle_root << '|' << h.timestamp_ms << '|'
      << h.difficulty_bits << '|' << h.miner << '|';
    return o.str();
}

std::string block_hash(const BlockHeader& h) {
    std::string data = header_prefix(h) + std::to_string(h.nonce);
    return crypto::to_hex(crypto::sha256d(data.data(), data.size()));
}

bool meets_difficulty(const std::string& hash_hex, int bits) {
    return crypto::leading_zero_bits_hex(hash_hex) >= bits;
}

BlockHeader genesis_header() {
    BlockHeader g;
    g.height = 0;
    g.prev_hash = kZeroHash;
    g.merkle_root = kZeroHash;
    g.timestamp_ms = 1767225600000;  // 2026-01-01T00:00:00Z
    g.difficulty_bits = 0;
    g.miner = "genesis";
    g.nonce = 0;
    return g;
}

}  // namespace chain
