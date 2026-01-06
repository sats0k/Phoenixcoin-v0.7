// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#pragma once

#include <vector>
#include <memory>
#include <cstdint>

#include "uint256.h"
#include "key.h"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "This Hybrid implementation requires OpenSSL 3.5+"
#endif

enum class SigAlg : uint8_t {
    ECDSA_SECP256K1 = 0x01,
    DILITHIUM      = 0x02,
};

struct Signature {
    SigAlg alg;
    std::vector<uint8_t> sig;
};

class ISigner {
public:
    virtual ~ISigner() = default;
    virtual SigAlg Algorithm() const = 0;
    virtual bool Sign(const uint256& hash,
                      std::vector<uint8_t>& sig) const = 0;
    virtual bool Verify(const uint256& hash,
                        const std::vector<uint8_t>& sig) const = 0;
    virtual std::vector<uint8_t> GetPublicKey() const = 0;
};

class Secp256k1Signer final : public ISigner {
    CKey key;
public:
    explicit Secp256k1Signer(const CKey& k);
    SigAlg Algorithm() const override;
    bool Sign(const uint256&, std::vector<uint8_t>&) const override;
    bool Verify(const uint256&, const std::vector<uint8_t>&) const override;
    std::vector<uint8_t> GetPublicKey() const override;
};

class DilithiumSigner final : public ISigner {
    EVP_PKEY* pkey;
public:
    explicit DilithiumSigner(EVP_PKEY* k);
    ~DilithiumSigner() override;

    SigAlg Algorithm() const override;
    bool Sign(const uint256&, std::vector<uint8_t>&) const override;
    bool Verify(const uint256&, const std::vector<uint8_t>&) const override;
    std::vector<uint8_t> GetPublicKey() const override;
};

class HybridSigner {
    std::vector<std::unique_ptr<ISigner>> signers;
public:
    void Add(std::unique_ptr<ISigner>);
    bool SignAll(const uint256&, std::vector<Signature>&) const;
    bool VerifyAll(const uint256&, const std::vector<Signature>&) const;
};
