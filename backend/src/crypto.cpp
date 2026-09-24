#include "crypto.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>
#include <stdexcept>

namespace crypto {

namespace {

struct PkeyDel { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct MdCtxDel { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct BioDel { void operator()(BIO* p) const { BIO_free(p); } };
struct SigDel { void operator()(ECDSA_SIG* p) const { ECDSA_SIG_free(p); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDel>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDel>;
using BioPtr = std::unique_ptr<BIO, BioDel>;
using SigPtr = std::unique_ptr<ECDSA_SIG, SigDel>;

PkeyPtr load_spki(const std::string& spki_b64) {
    Bytes der;
    if (!base64_decode(spki_b64, der) || der.empty()) return nullptr;
    const unsigned char* p = der.data();
    return PkeyPtr(d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size())));
}

}  // namespace

Bytes sha256(const void* data, size_t len) {
    Bytes out(32);
    unsigned int n = 0;
    EVP_Digest(data, len, out.data(), &n, EVP_sha256(), nullptr);
    return out;
}

Bytes sha256d(const void* data, size_t len) {
    Bytes first = sha256(data, len);
    return sha256(first.data(), first.size());
}

std::string sha256_hex(const std::string& s) { return to_hex(sha256(s.data(), s.size())); }
std::string sha256_hex(const Bytes& b) { return to_hex(sha256(b.data(), b.size())); }

std::string to_hex(const unsigned char* d, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        out[2 * i] = digits[d[i] >> 4];
        out[2 * i + 1] = digits[d[i] & 0xF];
    }
    return out;
}

bool from_hex(const std::string& hex, Bytes& out) {
    if (hex.size() % 2) return false;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = val(hex[2 * i]), lo = val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

std::string base64_encode(const Bytes& b) {
    if (b.empty()) return "";
    std::string out(4 * ((b.size() + 2) / 3), '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), b.data(), static_cast<int>(b.size()));
    out.resize(n);
    return out;
}

bool base64_decode(const std::string& in, Bytes& out) {
    std::string s;
    s.reserve(in.size());
    for (char c : in)
        if (c != '\n' && c != '\r' && c != ' ') s.push_back(c);
    if (s.empty()) {
        out.clear();
        return true;
    }
    if (s.size() % 4) return false;
    out.resize(3 * s.size() / 4);
    int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()), static_cast<int>(s.size()));
    if (n < 0) return false;
    size_t pad = 0;
    if (s.back() == '=') ++pad;
    if (s.size() > 1 && s[s.size() - 2] == '=') ++pad;
    out.resize(static_cast<size_t>(n) - pad);
    return true;
}

int leading_zero_bits(const unsigned char* d, size_t n) {
    int bits = 0;
    for (size_t i = 0; i < n; ++i) {
        if (d[i] == 0) {
            bits += 8;
            continue;
        }
        for (int b = 7; b >= 0; --b) {
            if (d[i] & (1u << b)) return bits;
            ++bits;
        }
    }
    return bits;
}

int leading_zero_bits_hex(const std::string& hex) {
    Bytes b;
    if (!from_hex(hex, b)) return -1;
    return leading_zero_bits(b.data(), b.size());
}

KeyPair generate_p256() {
    PkeyPtr pkey(EVP_EC_gen("P-256"));
    if (!pkey) throw std::runtime_error("EC key generation failed");

    BioPtr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);

    KeyPair kp;
    kp.private_pem.assign(data, static_cast<size_t>(len));
    int dlen = i2d_PUBKEY(pkey.get(), nullptr);
    Bytes der(static_cast<size_t>(dlen));
    unsigned char* p = der.data();
    i2d_PUBKEY(pkey.get(), &p);
    kp.public_spki_b64 = base64_encode(der);
    return kp;
}

std::string sign_p256(const std::string& private_pem, const std::string& msg) {
    BioPtr bio(BIO_new_mem_buf(private_pem.data(), static_cast<int>(private_pem.size())));
    PkeyPtr pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if (!pkey) return "";
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) return "";
    size_t len = 0;
    auto m = reinterpret_cast<const unsigned char*>(msg.data());
    if (EVP_DigestSign(ctx.get(), nullptr, &len, m, msg.size()) != 1) return "";
    Bytes der(len);
    if (EVP_DigestSign(ctx.get(), der.data(), &len, m, msg.size()) != 1) return "";

    const unsigned char* p = der.data();
    SigPtr sig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(len)));
    if (!sig) return "";
    const BIGNUM *r = nullptr, *s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    unsigned char raw[64];
    BN_bn2binpad(r, raw, 32);
    BN_bn2binpad(s, raw + 32, 32);
    return to_hex(raw, 64);
}

bool verify_p256(const std::string& spki_b64, const std::string& msg, const std::string& sig_hex) {
    PkeyPtr pkey = load_spki(spki_b64);
    if (!pkey) return false;
    Bytes raw;
    if (!from_hex(sig_hex, raw) || raw.size() != 64) return false;

    // WebCrypto emits raw r||s; OpenSSL verifies DER, so re-encode.
    SigPtr sig(ECDSA_SIG_new());
    BIGNUM* r = BN_bin2bn(raw.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + 32, 32, nullptr);
    if (!r || !s || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
        BN_free(r);
        BN_free(s);
        return false;
    }
    int dlen = i2d_ECDSA_SIG(sig.get(), nullptr);
    Bytes der(static_cast<size_t>(dlen));
    unsigned char* q = der.data();
    i2d_ECDSA_SIG(sig.get(), &q);

    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) return false;
    return EVP_DigestVerify(ctx.get(), der.data(), der.size(),
                            reinterpret_cast<const unsigned char*>(msg.data()), msg.size()) == 1;
}

std::string fingerprint(const std::string& spki_b64) {
    Bytes der;
    if (!base64_decode(spki_b64, der)) return "";
    return sha256_hex(der);
}

bool is_p256_spki(const std::string& spki_b64) {
    PkeyPtr pkey = load_spki(spki_b64);
    if (!pkey || !EVP_PKEY_is_a(pkey.get(), "EC")) return false;
    char group[64] = {0};
    size_t glen = 0;
    if (EVP_PKEY_get_utf8_string_param(pkey.get(), "group", group, sizeof(group), &glen) != 1) return false;
    std::string g(group, glen);
    return g == "prime256v1" || g == "P-256";
}

MidstateHasher::MidstateHasher(const std::string& prefix) {
    EVP_MD* md = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    md_ = md;
    auto* base = EVP_MD_CTX_new();
    EVP_DigestInit_ex(base, md, nullptr);
    EVP_DigestUpdate(base, prefix.data(), prefix.size());
    base_ = base;
    work_ = EVP_MD_CTX_new();
    outer_ = EVP_MD_CTX_new();
}

MidstateHasher::~MidstateHasher() {
    EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(outer_));
    EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(work_));
    EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(base_));
    EVP_MD_free(static_cast<EVP_MD*>(md_));
}

void MidstateHasher::hash(const char* suffix, size_t len, unsigned char out[32]) {
    auto* work = static_cast<EVP_MD_CTX*>(work_);
    auto* outer = static_cast<EVP_MD_CTX*>(outer_);
    unsigned char first[32];
    unsigned int n = 0;
    EVP_MD_CTX_copy_ex(work, static_cast<EVP_MD_CTX*>(base_));
    EVP_DigestUpdate(work, suffix, len);
    EVP_DigestFinal_ex(work, first, &n);
    EVP_DigestInit_ex(outer, static_cast<EVP_MD*>(md_), nullptr);
    EVP_DigestUpdate(outer, first, 32);
    EVP_DigestFinal_ex(outer, out, &n);
}

}  // namespace crypto
