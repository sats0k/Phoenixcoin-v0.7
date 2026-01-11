// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "hybrid_signer.h"

/* ---------- secp256k1 ---------- */

Secp256k1Signer::Secp256k1Signer(const CKey& k) : key(k) {}

SigAlg Secp256k1Signer::Algorithm() const { return SigAlg::ECDSA_SECP256K1; }

bool Secp256k1Signer::Sign(const uint256& h, std::vector<uint8_t>& s) const {
    return key.Sign(h, s);
}

bool Secp256k1Signer::Verify(const uint256& h,
                             const std::vector<uint8_t>& s) const {
    return key.Verify(h, s);
}

std::vector<uint8_t> Secp256k1Signer::GetPublicKey() const {
    return key.GetPubKey().Raw();
}

/* ---------- Dilithium ---------- */

DilithiumSigner::DilithiumSigner(EVP_PKEY* k) : pkey(k) {}

DilithiumSigner::~DilithiumSigner() {
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
}

SigAlg DilithiumSigner::Algorithm() const { return SigAlg::DILITHIUM; }

bool DilithiumSigner::Sign(const uint256& h, std::vector<uint8_t>& s) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    size_t len = 0;
    if (EVP_DigestSign(ctx, nullptr, &len, h.begin(), 32) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    s.resize(len);
    bool ok = EVP_DigestSign(ctx, s.data(), &len, h.begin(), 32) > 0;
    s.resize(len);

    EVP_MD_CTX_free(ctx);
    return ok;
}

bool DilithiumSigner::Verify(const uint256& h,
                             const std::vector<uint8_t>& s) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    bool ok = EVP_DigestVerify(ctx, s.data(), s.size(), h.begin(), 32) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

std::vector<uint8_t> DilithiumSigner::GetPublicKey() const {
    size_t len = 0;

    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) <= 0) {
        return {};
    }

    std::vector<uint8_t> out(len);
    if (EVP_PKEY_get_raw_public_key(pkey, out.data(), &len) <= 0) {
        return {};
    }
    out.resize(len);
    return out;
}

/* ---------- Hybrid ---------- */

void HybridSigner::Add(std::unique_ptr<ISigner> s) {
    signers.push_back(std::move(s));
}

bool HybridSigner::SignAll(const uint256& h,
                           std::vector<Signature>& sigs) const {
    sigs.clear();
    for (const auto& s : signers) {
        Signature sig;
        sig.alg = s->Algorithm();
        if (!s->Sign(h, sig.sig)) return false;
        sigs.push_back(std::move(sig));
    }
    return true;
}

bool HybridSigner::VerifyAll(const uint256& h,
                             const std::vector<Signature>& sigs) const {
    if (sigs.size() != signers.size()) return false;

    for (size_t i = 0; i < sigs.size(); ++i) {
        if (sigs[i].alg != signers[i]->Algorithm()) return false;
        if (!signers[i]->Verify(h, sigs[i].sig)) return false;
    }
    return true;
}

/* ---------- Cryptography Operations ---------- */

void PerformCryptography() {
    // Generate secp256k1 key
    CKey secpKey;
    secpKey.MakeNewKey(true);

    // Generate Dilithium key
    EVP_PKEY_CTX* kctx =
        EVP_PKEY_CTX_new_from_name(nullptr, "p384_mldsa65", nullptr);
    if (!kctx) return;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return;
    }
    EVP_PKEY_CTX_free(kctx);

    // Prepare a hash
    uint256 hash;
    uint8_t data[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    std::memcpy(hash.begin(), data, 32);

    // Create hybrid signer
    HybridSigner hs;
    hs.Add(std::make_unique<Secp256k1Signer>(secpKey));
    hs.Add(std::make_unique<DilithiumSigner>(pkey));
    pkey = nullptr;  // Release ownership

    // Sign the hash
    std::vector<Signature> sigs;
    if (!hs.SignAll(hash, sigs)) return;

    // Verify signatures
    if (!hs.VerifyAll(hash, sigs)) return;

    // Cleanup is handled by destructors
}

/* ---------- Serialization, Deserialization ---------- */

// Extracts raw public and private keys from an EVP_PKEY object
static bool GetRawKey(EVP_PKEY* pkey, std::vector<uint8_t>& pub,
                      std::vector<uint8_t>& priv) {
    size_t len = 0;

    // Get raw public key
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) <= 0) return false;
    pub.resize(len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) <= 0) return false;

    // Get raw private key
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &len) <= 0) return false;
    priv.resize(len);
    if (EVP_PKEY_get_raw_private_key(pkey, priv.data(), &len) <= 0)
        return false;

    return true;
}

// Serialize a MLDSA key into a custom format
std::vector<uint8_t> SerializeMLDSAKey(EVP_PKEY* pkey) {
    std::vector<uint8_t> pub, priv;
    if (!GetRawKey(pkey, pub, priv)) return {};

    std::vector<uint8_t> out;
    out.reserve(1 + 2 + pub.size() + 2 + priv.size());

    // Algorithm identifier
    out.push_back(static_cast<uint8_t>(SigAlg::DILITHIUM));

    // Helper lambda to push uint16_t in big-endian
    auto push16 = [&](uint16_t v) {
        out.push_back(v >> 8);
        out.push_back(v & 0xff);
    };

    // Append public key
    push16(pub.size());
    out.insert(out.end(), pub.begin(), pub.end());

    // Append private key
    push16(priv.size());
    out.insert(out.end(), priv.begin(), priv.end());

    return out;
}

// Deserialize the custom format to reconstruct EVP_PKEY
EVP_PKEY* DeserializeMLDSAKey(const std::vector<uint8_t>& in) {
    if (in.size() < 5) return nullptr;

    size_t off = 0;
    uint8_t alg = in[off++];
    if (alg != static_cast<uint8_t>(SigAlg::DILITHIUM)) return nullptr;

    auto read16 = [&](uint16_t& v) {
        if (off + 2 > in.size()) return false;
        v = (in[off] << 8) | in[off + 1];
        off += 2;
        return true;
    };

    uint16_t pub_len, priv_len;

    // Read public key length
    if (!read16(pub_len)) return nullptr;
    if (off + pub_len > in.size()) return nullptr;
    const uint8_t* pub = &in[off];
    off += pub_len;

    // Read private key length
    if (!read16(priv_len)) return nullptr;
    if (off + priv_len > in.size()) return nullptr;
    const uint8_t* priv = &in[off];

    // Create EVP_PKEY from raw private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ML_DSA_65, nullptr,
                                                  priv, priv_len);
    if (!pkey) return nullptr;

    // Verify the public key matches
    size_t len = 0;
    EVP_PKEY_get_raw_public_key(pkey, nullptr, &len);
    std::vector<uint8_t> check(len);
    EVP_PKEY_get_raw_public_key(pkey, check.data(), &len);

    if (check.size() != pub_len ||
        CRYPTO_memcmp(check.data(), pub, pub_len) != 0) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    return pkey;
}

// Serialize a Dilithium signer private key
std::vector<uint8_t> DilithiumSigner::SerializePrivateKey() const {
    std::vector<uint8_t> pub, priv;
    if (!GetRawKey(pkey, pub, priv)) return {};

    std::vector<uint8_t> out;
    out.reserve(1 + 2 + pub.size() + 2 + priv.size());

    // Algorithm identifier
    out.push_back(static_cast<uint8_t>(SigAlg::DILITHIUM));

    auto push16 = [&](uint16_t v) {
        out.push_back(v >> 8);
        out.push_back(v & 0xff);
    };

    // Append public key
    push16(pub.size());
    out.insert(out.end(), pub.begin(), pub.end());

    // Append private key
    push16(priv.size());
    out.insert(out.end(), priv.begin(), priv.end());

    // Cleanse private key data
    OPENSSL_cleanse(priv.data(), priv.size());

    return out;
}

// Deserialize data into a DilithiumSigner object
std::unique_ptr<DilithiumSigner> DilithiumSigner::FromSerialized(
    const std::vector<uint8_t>& in) {
    if (in.size() < 5) return nullptr;

    size_t off = 0;
    if (in[off++] != static_cast<uint8_t>(SigAlg::DILITHIUM)) return nullptr;

    auto read16 = [&](uint16_t& v) {
        if (off + 2 > in.size()) return false;
        v = (in[off] << 8) | in[off + 1];
        off += 2;
        return true;
    };

    uint16_t pub_len, priv_len;

    // Read public key length
    if (!read16(pub_len) || off + pub_len > in.size()) return nullptr;
    const uint8_t* pub = &in[off];
    off += pub_len;

    // Read private key length
    if (!read16(priv_len) || off + priv_len > in.size()) return nullptr;
    const uint8_t* priv = &in[off];

    // Create EVP_PKEY from raw private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ML_DSA_65, nullptr,
                                                  priv, priv_len);
    if (!pkey) return nullptr;

    // Verify public key matches
    size_t len = 0;
    EVP_PKEY_get_raw_public_key(pkey, nullptr, &len);
    if (len != pub_len) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    std::vector<uint8_t> check(len);
    EVP_PKEY_get_raw_public_key(pkey, check.data(), &len);

    if (CRYPTO_memcmp(check.data(), pub, pub_len) != 0) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    return std::make_unique<DilithiumSigner>(pkey);
}

// Serialize multiple private keys from signers
std::vector<std::vector<uint8_t>> HybridSigner::SerializePrivateKeys() const {
    std::vector<std::vector<uint8_t>> out;
    for (const auto& s : signers) {
        out.push_back(s->SerializePrivateKey());
    }
    return out;
}

// Load a hybrid signer with a secp256k1 signer and multiple Dilithium signers
HybridSigner LoadHybridSigner(const CKey& secpKey,
                              const std::vector<std::vector<uint8_t>>& keys) {
    HybridSigner hs;
    hs.Add(std::make_unique<Secp256k1Signer>(secpKey));

    for (const auto& k : keys) {
        auto d = DilithiumSigner::FromSerialized(k);
        if (d) hs.Add(std::move(d));
    }

    return hs;
}
