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
        EVP_PKEY_CTX_new_from_name(nullptr, "Dilithium3", nullptr);
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
