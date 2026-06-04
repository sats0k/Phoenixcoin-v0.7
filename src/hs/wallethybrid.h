// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef WALLETHYBRID_H
#define WALLETHYBRID_H

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <stdexcept>

#include "key.h"
#include "serialize.h"
#include "uint256.h"
#include "sync.h"
#include "hs/crypto_context.h"
#include "hs/hybrid_signer.h"

class CWallet;
class CKeyID;

// -----------------------------
// Hybrid key versions
// -----------------------------
enum HybridKeyVersion : uint8_t {
    HYBRIDKEY_V1 = 1,  // legacy (seed-based MLDSA)
};

// -----------------------------
// In-memory representation
// -----------------------------
struct CHybridKey
{
    CPrivKey secpPriv;
    CPubKey  secpPub;

    std::string mldsaAlg;
    std::unique_ptr<MLDSASigner> mldsaSigner;

    int64_t nCreateTime = 0;

    CHybridKey() = default;

    CKeyID GetKeyID() const { return secpPub.GetID(); }

    CKey GetCKey() const
    {
        CKey key;
        if (!key.SetPrivKey(secpPriv))
            throw std::runtime_error("Invalid secp key");
        key.SetPubKey(secpPub);
        return key;
    }
};

// -----------------------------
// On-disk representation
// -----------------------------
class CHybridKeyDisk
{
public:
    uint8_t  nVersion = 2;      // wallet serialization version
    int32_t  nCreateTime = 0;

    // secp256k1
    CPrivKey secpPriv;
    CPubKey  secpPub;

    // MLDSA
    std::string mldsaAlg;
    std::vector<unsigned char> mldsaPrivKey; // DER-encoded EVP_PKEY

    uint256 hashChecksum;

    void ComputeChecksum();
    bool CheckChecksum() const;
    static CHybridKeyDisk FromMemory(const CHybridKey& hk);

    IMPLEMENT_SERIALIZE(
        READWRITE(nVersion);
        READWRITE(nCreateTime);
        READWRITE(secpPriv);
        READWRITE(secpPub);

        if (nVersion >= 2) {
            READWRITE(mldsaAlg);
            READWRITE(mldsaPrivKey);
        }

        READWRITE(hashChecksum);
    )
};

// -----------------------------
// Hybrid key helpers
// -----------------------------
void GenerateHybridKey(CHybridKey& hk);
std::unique_ptr<MLDSASigner> GetSignerFromKey(const CHybridKey& hk);

// -----------------------------
// Wallet integration
// -----------------------------
bool LoadHybridKey(class CWallet* wallet, const CHybridKeyDisk& disk);
void NewHybridKeyPool(class CWallet* wallet, int nSize);

#endif  // WALLETHYBRID_H
