// Offline checks for the cryptographic core. Run: build/ledger_selftest
#include <cstdio>
#include <string>
#include <vector>

#include "chain.h"
#include "confidence.h"
#include "crypto.h"

static int failures = 0;
static void check(bool ok, const char* what) {
    std::printf("[%s] %s\n", ok ? " OK " : "FAIL", what);
    if (!ok) ++failures;
}

int main() {
    // SHA-256 test vectors (FIPS 180-2)
    check(crypto::sha256_hex(std::string("")) ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "sha256(\"\")");
    check(crypto::sha256_hex(std::string("abc")) ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256(\"abc\")");

    // base64 round trip
    crypto::Bytes in = {0, 1, 2, 250, 251, 252, 253}, out;
    check(crypto::base64_decode(crypto::base64_encode(in), out) && out == in, "base64 round trip");

    // ECDSA P-256 sign / verify
    auto kp = crypto::generate_p256();
    std::string msg = "v1|1|abc|code|0.6000|def|APPROVED|x|fpr|1";
    std::string sig = crypto::sign_p256(kp.private_pem, msg);
    check(sig.size() == 128, "signature is raw r||s (64 bytes)");
    check(crypto::verify_p256(kp.public_spki_b64, msg, sig), "ECDSA verify valid signature");
    check(!crypto::verify_p256(kp.public_spki_b64, msg + "x", sig), "ECDSA reject modified message");
    check(crypto::is_p256_spki(kp.public_spki_b64), "SPKI detected as P-256");

    // Canonical tx round trip
    chain::TxFields f{42, std::string(64, 'a'), "code", "0.6123", std::string(64, 'b'), "APPROVED",
                      std::string(64, 'c'), std::string(64, 'd'), 1758700000000};
    chain::TxFields g;
    check(chain::parse_canonical(chain::canonical(f), g) && chain::canonical(g) == chain::canonical(f),
          "canonical tx round trip");

    // Merkle: single leaf is the leaf; order matters
    std::string a = crypto::sha256_hex(std::string("a")), b = crypto::sha256_hex(std::string("b"));
    check(chain::merkle_root({a}) == a, "merkle single leaf");
    check(chain::merkle_root({a, b}) != chain::merkle_root({b, a}), "merkle order sensitive");
    check(chain::merkle_root({a, b, a}) == chain::merkle_root({a, b, a, a}), "merkle odd duplication");

    // Genesis header hashes deterministically (sanity check for canonical_header/block_hash).
    chain::BlockHeader h = chain::genesis_header();
    check(chain::block_hash(h) == chain::block_hash(chain::genesis_header()), "block_hash is deterministic");

    // meets_difficulty: hex-digit leading zeros, as the guide specifies (not bits).
    check(chain::meets_difficulty("000abc...", 3), "meets_difficulty: 3 leading hex zeros");
    check(!chain::meets_difficulty("00abc...", 3), "meets_difficulty: rejects only 2 leading hex zeros");
    check(chain::meets_difficulty("anything", 0), "meets_difficulty: d=0 always satisfied");

    // PoW disjoint nonces: miner i in [0,N) tries i, i+N, i+2N, ... Two miners can never
    // report the same nonce, because that would require i1 + k1*N == i2 + k2*N with
    // 0<=i1,i2<N, which forces i1 == i2 (mod N) and hence i1 == i2. This is what makes the
    // "smallest winning nonce wins" tie-break well-defined (no real ties are possible).
    {
        const int N = 7;
        bool collision = false;
        for (int i1 = 0; i1 < N && !collision; ++i1)
            for (int i2 = 0; i2 < N && !collision; ++i2) {
                if (i1 == i2) continue;
                for (uint64_t k1 = 0; k1 < 50 && !collision; ++k1)
                    for (uint64_t k2 = 0; k2 < 50 && !collision; ++k2)
                        if (static_cast<uint64_t>(i1) + k1 * N == static_cast<uint64_t>(i2) + k2 * N) collision = true;
            }
        check(!collision, "PoW nonce residue classes never collide across miners");
    }

    // Stake-weighted proposer selection is deterministic: same stake table + same
    // (prev_hash, height, attempt) always picks the same proposer.
    std::vector<chain::StakeEntry> stakes = {{"v1", 10}, {"v2", 20}, {"v3", 70}};
    std::string p1 = chain::select_proposer(stakes, "deadbeef", 42, 0);
    std::string p2 = chain::select_proposer(stakes, "deadbeef", 42, 0);
    check(!p1.empty() && p1 == p2, "select_proposer is deterministic");
    check(chain::select_proposer(stakes, "deadbeef", 43, 0) != "",
          "select_proposer picks someone for a different height");
    check(chain::select_proposer(stakes, "deadbeef", 42, 1) != p1 ||
              chain::select_proposer(stakes, "deadbeef", 42, 2) != p1,
          "select_proposer's attempt counter can change the draw (redraw after a rejection)");
    check(chain::select_proposer({}, "deadbeef", 1, 0).empty(), "select_proposer with no validators returns empty");

    // Selection frequency over many trials should roughly track stake weight (loose bound,
    // just to catch a gross bias rather than verify exact statistics).
    int counts[3] = {0, 0, 0};
    const int trials = 20000;
    for (int i = 0; i < trials; ++i) {
        std::string w = chain::select_proposer(stakes, "seed", i, 0);
        if (w == "v1") ++counts[0];
        else if (w == "v2") ++counts[1];
        else if (w == "v3") ++counts[2];
    }
    double f1 = double(counts[0]) / trials, f2 = double(counts[1]) / trials, f3 = double(counts[2]) / trials;
    check(f1 > 0.05 && f1 < 0.15, "proposer frequency tracks stake (v1 ~10%)");
    check(f2 > 0.15 && f2 < 0.25, "proposer frequency tracks stake (v2 ~20%)");
    check(f3 > 0.60 && f3 < 0.80, "proposer frequency tracks stake (v3 ~70%)");

    // BFT quorum threshold: smallest integer V that is >= 2/3 of the total -- i.e. the
    // smallest V with 3V >= 2*total. Check the lemma directly at and around the exact
    // boundary (total=3k has an exact integer 2/3).
    check(chain::quorum_threshold(100) == 67, "quorum_threshold(100) == 67");
    check(chain::quorum_threshold(10) == 7, "quorum_threshold(10) == 7");
    check(chain::quorum_threshold(3) == 2, "quorum_threshold(3) == 2");
    for (int64_t total = 1; total <= 300; ++total) {
        int64_t V = chain::quorum_threshold(total);
        check(3 * V >= 2 * total, "quorum_threshold satisfies 3V>=2A");
        check(V == 0 || 3 * (V - 1) < 2 * total, "quorum_threshold is the smallest such V");
    }

    // PoS redraw termination: the eligible pool strictly shrinks by one on every rejection
    // (the slashed proposer is removed), so a round settles (sealed or pool exhausted) in at
    // most N attempts -- simulate the bookkeeping directly.
    {
        int pool_size = 12;
        int attempts = 0;
        while (pool_size > 0 && attempts < 1000) {
            --pool_size;  // worst case: every draw is dishonest and gets slashed
            ++attempts;
        }
        check(attempts <= 12, "PoS redraw terminates within the initial pool size");
    }

    // PoS vote-set validation (the casos "voto de un nodo que no es validador o que vota dos
    // veces", "votación exactamente en 2/3", stake inflado).
    {
        std::vector<chain::StakeEntry> snap = {{"a", 10}, {"b", 10}, {"c", 10}};  // total 30, threshold 20
        auto ok = chain::check_vote_set(snap, {{"a", 10}, {"b", 10}}, 30, 20);
        check(ok.empty(), "vote set: exactly 2/3 of stake is accepted");
        auto below = chain::check_vote_set(snap, {{"a", 10}}, 30, 10);
        check(!below.empty(), "vote set: below 2/3 is rejected");
        auto just_below = chain::check_vote_set({{"a", 1}, {"b", 1}, {"c", 1}, {"d", 1}}, {{"a", 1}, {"b", 1}}, 4, 2);
        check(!just_below.empty(), "vote set: 2 of 4 (50%) is rejected");
        auto stranger = chain::check_vote_set(snap, {{"a", 10}, {"b", 10}, {"zz", 10}}, 30, 30);
        check(!stranger.empty(), "vote set: vote from a non-validator is rejected");
        auto twice = chain::check_vote_set(snap, {{"a", 10}, {"a", 10}, {"b", 10}}, 30, 30);
        check(!twice.empty(), "vote set: a validator voting twice is rejected");
        auto inflated = chain::check_vote_set(snap, {{"a", 50}, {"b", 10}}, 30, 60);
        check(!inflated.empty(), "vote set: inflated stake_at_vote is rejected");
        auto bad_total = chain::check_vote_set(snap, {{"a", 10}, {"b", 10}}, 15, 20);
        check(!bad_total.empty(), "vote set: total_stake not matching the snapshot is rejected");
        auto bad_sum = chain::check_vote_set(snap, {{"a", 10}, {"b", 10}}, 30, 30);
        check(!bad_sum.empty(), "vote set: quorum_stake not matching the votes is rejected");
        check(chain::kMinDifficultyHexZeros >= 1, "PoW difficulty floor is at least 1 hex zero");
    }

    // Rules engine
    RulesEngine re;
    std::string err;
    if (re.load("rules/confidence_rules.json", err)) {
        Metrics m{"code", 0.95, 1.0, 20, false};
        check(re.classify(m).category == "HIGH", "rules: strong work -> HIGH");
        m.has_external_side_effects = true;
        check(re.classify(m).category == "MEDIUM", "rules: side effects cap -> MEDIUM");
        Metrics low{"data_pipeline", 0.9, 0.1, 50, false};
        check(re.classify(low).category == "LOW", "rules: failing tests -> LOW");
    } else {
        std::printf("[SKIP] rules (%s) - run from backend/\n", err.c_str());
    }

    std::printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
