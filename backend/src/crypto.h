#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Thin wrappers over OpenSSL 3 (EVP API). All signatures are ECDSA P-256 / SHA-256,
// encoded as raw r||s (64 bytes, hex) — the same format WebCrypto produces in the browser.
namespace crypto {

using Bytes = std::vector<unsigned char>;

Bytes sha256(const void* data, size_t len);
std::string sha256_hex(const std::string& s);
std::string sha256_hex(const Bytes& b);
// Double SHA-256 (as used for Bitcoin headers and merkle nodes).
Bytes sha256d(const void* data, size_t len);

std::string to_hex(const unsigned char* d, size_t n);
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
bool from_hex(const std::string& hex, Bytes& out);

std::string base64_encode(const Bytes& b);
bool base64_decode(const std::string& s, Bytes& out);

struct KeyPair {
    std::string private_pem;
    std::string public_spki_b64;
};
KeyPair generate_p256();
// Returns raw r||s signature as 128 hex chars, or "" on failure.
std::string sign_p256(const std::string& private_pem, const std::string& msg);
bool verify_p256(const std::string& spki_b64, const std::string& msg, const std::string& sig_hex);
// SHA-256 of the DER SubjectPublicKeyInfo, hex. Used as the auditor's on-chain identity.
std::string fingerprint(const std::string& spki_b64);
bool is_p256_spki(const std::string& spki_b64);

}  // namespace crypto
