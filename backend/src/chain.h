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
// Shared by both consensus modes: PoW leaves proposer/votes empty-ish (quorum=total=0) and
// uses nonce/difficulty_hex_zeros; PoS leaves nonce=0, difficulty_hex_zeros=0 and uses
// proposer + the quorum fields (tracked alongside, in BlockRow/votes, not in the header
// itself). nonce and difficulty_hex_zeros DO live in the header because the guide requires
// the block hash to cover them regardless of mode.
struct BlockHeader {
    int64_t height = 0;
    std::string prev_hash;
    std::string merkle_root;
    int64_t timestamp_ms = 0;
    std::string proposer;          // winning miner (PoW) or sorteed validator (PoS)
    uint64_t nonce = 0;             // PoW: winning nonce. PoS: always 0.
    int difficulty_hex_zeros = 0;   // PoW: required leading hex zero digits. PoS: always 0.
};

std::string canonical_header(const BlockHeader& h);
std::string block_hash(const BlockHeader& h);

// True iff hash_hex starts with `hex_zeros` '0' characters (PoW target, in hex digits as the
// guide specifies -- not bits).
bool meets_difficulty(const std::string& hash_hex, int hex_zeros);

extern const char* kZeroHash;
BlockHeader genesis_header();

// ---------- Proof-of-stake selection ----------
struct StakeEntry {
    std::string name;
    int64_t stake = 0;
};

// Deterministic, stake-weighted leader election ("sorteo"): seeds on (prev_hash, height,
// attempt) so anyone who knows the same stake table can recompute the same proposer, with no
// coordinator and no computation race. `attempt` starts at 0 and increments on every redraw
// after a rejected proposal, so a redraw never repeats the same draw. Returns "" if the stake
// table is empty or totals zero stake.
std::string select_proposer(const std::vector<StakeEntry>& stakes, const std::string& prev_hash, int64_t height,
                            int attempt);

// Smallest integer V that is >= 2/3 of total_stake (the BFT quorum requirement): the smallest
// V with 3V >= 2*total_stake.
int64_t quorum_threshold(int64_t total_stake);

// Lowest PoW difficulty a committed block may claim; without a floor a miner could "solve" a
// block at difficulty 0, which every hash satisfies.
constexpr int kMinDifficultyHexZeros = 1;

struct VoteStake {
    std::string name;
    int64_t stake = 0;
};

// Pure structural checks on a PoS block's vote set, against the stake table frozen at round
// time. Returns one message per violation (empty = fine):
//  - the recorded total_stake must equal the sum of the snapshot;
//  - every vote must come from a validator in the snapshot, at most once, carrying exactly the
//    stake the snapshot assigns it (a validator cannot inflate its own weight);
//  - quorum_stake must equal the sum of the votes and reach quorum_threshold(total_stake).
// Signature validity is checked separately by the caller (it needs the keys).
std::vector<std::string> check_vote_set(const std::vector<StakeEntry>& snapshot, const std::vector<VoteStake>& votes,
                                        int64_t total_stake, int64_t quorum_stake);

}  // namespace chain
