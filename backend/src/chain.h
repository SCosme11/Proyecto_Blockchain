#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Pure (DB-free) chain primitives: transactions, merkle trees, block headers.
namespace chain {

// ---------- Transactions ----------
// The auditor signs exactly the bytes of canonical(fields). Field order is fixed and
// '|'-delimited so the browser and the C++ node produce identical bytes without
// needing a JSON canonicalisation scheme.
struct TxFields {
    int64_t work_item_id = 0;
    std::string work_hash;      // SHA-256 of the agent's artifact
    std::string artifact_type;  // code | excel_model | report | data_pipeline | other
    std::string score;          // confidence score, fixed 4 decimals, e.g. "0.6120"
    std::string rules_hash;     // SHA-256 of the rule file that classified the work
    std::string decision;       // APPROVED | REJECTED
    std::string comment_hash;   // SHA-256 of the reviewer's comment (UTF-8)
    std::string auditor_fpr;    // SHA-256 of the reviewer's public key (SPKI DER)
    int64_t timestamp_ms = 0;   // reviewer's signing time
};

extern const char* kTxVersion;  // "v1"

std::string canonical(const TxFields& f);
bool parse_canonical(const std::string& s, TxFields& out);
// tx_id commits to both the payload and the signature.
std::string tx_id(const std::string& canonical, const std::string& sig_hex);

// ---------- Merkle ----------
// Bitcoin-style: double-SHA-256 of concatenated child hashes, last node duplicated on odd levels.
std::string merkle_root(const std::vector<std::string>& leaf_hex);

// ---------- Blocks ----------
struct BlockHeader {
    int64_t height = 0;
    std::string prev_hash;
    std::string merkle_root;
    int64_t timestamp_ms = 0;
    int difficulty_bits = 0;
    std::string miner;  // registered miner name; distinct per miner so each searches its own space
    uint64_t nonce = 0;
};

// Everything except the nonce, so the PoW loop can hash it once (midstate).
std::string header_prefix(const BlockHeader& h);
std::string block_hash(const BlockHeader& h);
bool meets_difficulty(const std::string& hash_hex, int bits);

extern const char* kZeroHash;
BlockHeader genesis_header();

}  // namespace chain
