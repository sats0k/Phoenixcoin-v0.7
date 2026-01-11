// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#pragma once

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include "key.h"
#include "uint256.h"

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "This Hybrid implementation requires OpenSSL 3.5+"
#endif

enum class SigAlg : uint8_t {
    ECDSA_SECP256K1 = 0x01,
    DILITHIUM = 0x02,
};

struct Signature {
    SigAlg alg;
    std::vector<uint8_t> sig;
};

class ISigner {
   public:
    virtual ~ISigner() = default;
    virtual SigAlg Algorithm() const = 0;
    virtual bool Sign(const uint256& h, std::vector<uint8_t>& sig) const = 0;
    virtual bool Verify(const uint256& h,
                        const std::vector<uint8_t>& sig) const = 0;
    virtual std::vector<uint8_t> GetPublicKey() const = 0;

    // NEW (optional)
    virtual std::vector<uint8_t> SerializePrivateKey() const { return {}; }
};

class Secp256k1Signer final : public ISigner {
    CKey key;

   public:
    explicit Secp256k1Signer(const CKey& k);
    SigAlg Algorithm() const override;
    bool Sign(const uint256& h, std::vector<uint8_t>& s) const override;
    bool Verify(const uint256& h, const std::vector<uint8_t>& s) const override;
    std::vector<uint8_t> GetPublicKey() const override;
};

class DilithiumSigner final : public ISigner {
    EVP_PKEY* pkey;

   public:
    explicit DilithiumSigner(EVP_PKEY* k);
    ~DilithiumSigner() override;

    SigAlg Algorithm() const override;
    bool Sign(const uint256& h, std::vector<uint8_t>& s) const override;
    bool Verify(const uint256& h, const std::vector<uint8_t>& s) const override;
    std::vector<uint8_t> GetPublicKey() const override;

    std::vector<uint8_t> SerializePrivateKey() const override;

    static std::unique_ptr<DilithiumSigner> FromSerialized(
        const std::vector<uint8_t>& in);
};

class HybridSigner {
    std::vector<std::unique_ptr<ISigner>> signers;

   public:
    void Add(std::unique_ptr<ISigner>);
    bool SignAll(const uint256& h, std::vector<Signature>& s) const;
    bool VerifyAll(const uint256& h, const std::vector<Signature>& s) const;
    std::vector<std::vector<uint8_t>> SerializePrivateKeys() const;
};
