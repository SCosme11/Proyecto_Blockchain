// Offline checks for the cryptographic core. Run: build/ledger_selftest
#include <chrono>
#include <cstdio>
#include <string>

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

    // Midstate hasher equals full hash
    chain::BlockHeader h = chain::genesis_header();
    h.nonce = 12345;
    crypto::MidstateHasher mh(chain::header_prefix(h));
    unsigned char d[32];
    std::string n = std::to_string(h.nonce);
    mh.hash(n.data(), n.size(), d);
    check(crypto::to_hex(d, 32) == chain::block_hash(h), "midstate hash == block_hash");

    // Mini PoW + hashrate
    h.difficulty_bits = 16;
    crypto::MidstateHasher pow(chain::header_prefix(h));
    auto t0 = std::chrono::steady_clock::now();
    uint64_t nonce = 0;
    for (;; ++nonce) {
        std::string s = std::to_string(nonce);
        pow.hash(s.data(), s.size(), d);
        if (crypto::leading_zero_bits(d, 32) >= 16) break;
    }
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    h.nonce = nonce;
    check(chain::meets_difficulty(chain::block_hash(h), 16), "PoW found for 16 bits");
    std::printf("       nonce=%llu  ~%.2f MH/s single thread\n", (unsigned long long)nonce,
                (nonce + 1) / secs / 1e6);

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
