// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "util.h"
#include "wallet.h"
#include "walletdb.h"
#include "init.h"
#include "serialize.h"
#include "hs/crypto_context.h"
#include "hs/hybrid_signer.h"
#include "hs/wallethybrid.h"

#include <memory>
#include <vector>
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

// -----------------------------
// CHybridKeyDisk
// -----------------------------
void CHybridKeyDisk::ComputeChecksum()
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << nVersion << nCreateTime << secpPriv << secpPub << mldsaAlg;
    ::WriteCompactSize(ss, mldsaPrivKey.size());
    if (!mldsaPrivKey.empty())
        ss.write((const char*)&mldsaPrivKey[0], mldsaPrivKey.size());
    hashChecksum = Hash(ss.begin(), ss.end());
}

bool CHybridKeyDisk::CheckChecksum() const
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << nVersion << nCreateTime << secpPriv << secpPub << mldsaAlg;
    ::WriteCompactSize(ss, mldsaPrivKey.size());
    if (!mldsaPrivKey.empty())
        ss.write((const char*)&mldsaPrivKey[0], mldsaPrivKey.size());
    return hashChecksum == Hash(ss.begin(), ss.end());
}

CHybridKeyDisk CHybridKeyDisk::FromMemory(const CHybridKey& hk)
{
    CHybridKeyDisk disk;
    disk.nVersion    = HYBRIDKEY_DISK_VERSION;
    disk.nCreateTime = hk.nCreateTime;
    disk.secpPriv    = hk.secpPriv;
    disk.secpPub     = hk.secpPub;
    disk.mldsaAlg    = hk.mldsaAlg;

    // Serialize MLDSA private key
    EVP_PKEY* pkey = hk.mldsaSigner->GetKey();
    if (!pkey)
        throw std::runtime_error("MLDSA signer has no key");

    unsigned char* buf = nullptr;
    int len = i2d_PrivateKey(pkey, &buf);
    if (len <= 0 || !buf)
        throw std::runtime_error("Failed to serialize MLDSA private key");

    disk.mldsaPrivKey.assign(buf, buf + len);
    OPENSSL_free(buf);

    disk.ComputeChecksum();
    return disk;
}

// -----------------------------
// Hybrid key helpers
// -----------------------------
void GenerateHybridKey(CHybridKey& hk)
{
    CKey key;
    key.MakeNewKey(true);
    hk.secpPriv = key.GetPrivKey();
    hk.secpPub  = key.GetPubKey();

    hk.mldsaSigner = MLDSASigner::GenerateNew();
    if (!hk.mldsaSigner)
        throw std::runtime_error("Failed to generate MLDSA key");

    hk.nCreateTime = GetTime();
    hk.mldsaAlg    = "p384_mldsa65";
}

std::unique_ptr<MLDSASigner> GetSignerFromKey(const CHybridKey& hk)
{
    if (!hk.mldsaSigner) {
        printf("Hybrid key has no MLDSA signer\n");
        return nullptr;
    }
    EVP_PKEY* pkey = hk.mldsaSigner->GetKey();
    if (!pkey) {
        printf("MLDSASigner contains no key\n");
        return nullptr;
    }
    EVP_PKEY_up_ref(pkey);
    return std::make_unique<MLDSASigner>(pkey);
}

// -----------------------------
// Wallet integration
// -----------------------------
bool LoadHybridKey(CWallet* wallet, const CHybridKeyDisk& disk)
{
    CHybridKey mem;
    std::unique_ptr<MLDSASigner> signer;

    // ---- Validate disk ----
    if (disk.nVersion != HYBRIDKEY_DISK_VERSION) {
        printf("FAIL: unsupported hybrid key disk version %u\n", disk.nVersion);
        return false;
    }
    if (!disk.CheckChecksum()) {
        printf("FAIL: checksum mismatch\n");
        return false;
    }
    if (disk.mldsaPrivKey.empty()) {
        printf("FAIL: empty MLDSA private key\n");
        return false;
    }

    try {
        // Deserialize secp key
        mem.nCreateTime = disk.nCreateTime;
        mem.secpPriv    = disk.secpPriv;
        mem.secpPub     = disk.secpPub;
        mem.mldsaAlg    = disk.mldsaAlg;

        CKey key;
        if (!key.SetPrivKey(mem.secpPriv) || !key.IsValid())
            throw std::runtime_error("invalid secp private key");
        key.SetPubKey(mem.secpPub);

        // Deserialize MLDSA key
        const unsigned char* p = disk.mldsaPrivKey.data();
        EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, disk.mldsaPrivKey.size());
        if (!pkey)
            throw std::runtime_error("MLDSA private key decode failed");

        // Construct MLDSASigner
        mem.mldsaSigner = std::make_unique<MLDSASigner>(pkey);
        signer = std::make_unique<MLDSASigner>(pkey);

        if (!ValidateHybridKey(mem))
            throw std::runtime_error("Hybrid key validation failed");

    } catch (const std::exception& e) {
        printf("LoadHybridKey failed: %s\n", e.what());
        return false;
    }

    // ---- Commit atomically ----
    CHybridKeyID hybridID = mem.GetHybridID();

    LOCK(wallet->cs_wallet);

    if (wallet->mapHybridKeys.count(hybridID)) {
        printf("WARNING: hybrid key %s already loaded\n", hybridID.ToString().c_str());
        return true;
    }

    wallet->mapHybridKeys.emplace(hybridID, std::move(mem));
    wallet->mapHybridSigners.emplace(hybridID, std::move(signer));

    printf("Hybrid key %s loaded successfully\n", hybridID.ToString().c_str());
    return true;
}

bool CWallet::EnsureHybridKey(const CKeyID& keyID)
{
    if (mapHybridSigners.count(keyID)) return true;

    CKey key;
    if (!GetKey(keyID, key)) return false;

    // ---- Stage 1: Build locally ----
    CHybridKey hk;
    std::unique_ptr<MLDSASigner> signer;

    try {
        hk.secpPriv = key.GetPrivKey();
        hk.secpPub  = key.GetPubKey();
        hk.nCreateTime = GetTime();
        hk.mldsaAlg = "p384_mldsa65";

        hk.mldsaSigner = MLDSASigner::GenerateNew();
        if (!hk.mldsaSigner) return false;

        if (!ValidateHybridKey(hk))
            return false;

        EVP_PKEY* pkey = hk.mldsaSigner->GetKey();
        if (!pkey) return false;

        EVP_PKEY_up_ref(pkey);
        signer = std::make_unique<MLDSASigner>(pkey);

    } catch (const std::exception& e) {
        printf("EnsureHybridKey(%s) failed: %s\n", keyID.ToString().c_str(), e.what());
        return false;
    }

    // Compute once
    CHybridKeyID hybridID = hk.GetHybridID();

    // ---- Stage 2: Persist to disk ----
    if (fFileBacked && !IsCrypted()) {
        try {
            CHybridKeyDisk disk = CHybridKeyDisk::FromMemory(hk);
            CWalletDB walletdb(strWalletFile);

            if (!walletdb.WriteHybridKey(hybridID, disk)) {
                printf("EnsureHybridKey(%s) DB write failed\n", keyID.ToString().c_str());
                return false;
            }
        } catch (const std::exception& e) {
            printf("EnsureHybridKey(%s) DB exception: %s\n", keyID.ToString().c_str(), e.what());
            return false;
        }
    }

    // ---- Stage 3: Commit to memory ----
    LOCK(cs_wallet);

    mapHybridKeys.emplace(hybridID, std::move(hk));
    mapHybridSigners.emplace(hybridID, std::move(signer));
    return true;
}

void NewHybridKeyPool(CWallet* wallet, int nSize)
{
    std::vector<std::pair<CHybridKeyID, CHybridKey>> stagedKeys;
    std::vector<std::pair<CHybridKeyID, CHybridKeyDisk>> stagedDisks;

    // Phase 1: Build locally
    try {
        for (int i = 0; i < nSize; ++i) {
            CHybridKey hk;
            GenerateHybridKey(hk);

            CHybridKeyID hybridID = hk.GetHybridID();
            stagedKeys.emplace_back(hk.GetHybridID(), std::move(hk));
            stagedDisks.emplace_back(hybridID, CHybridKeyDisk::FromMemory(stagedKeys.back().second));
        }
    } catch (const std::exception& e) {
        printf("ERROR: failed to generate hybrid key pool: %s\n", e.what());
        return;
    }

    // Phase 2: Persist to DB
    {
        CWalletDB walletdb(wallet->strWalletFile);
        walletdb.TxnBegin();
        bool success = true;
        for (const auto& entry : stagedDisks) {
            if (!walletdb.WriteHybridKey(entry.first, entry.second)) {
                printf("ERROR: failed to write hybrid key to DB\n");
                success = false;
                break;
            }
        }
        if (!success) {
            walletdb.TxnAbort();
            return;
        }
        walletdb.TxnCommit();
    }

    // Phase 3: Commit to memory
    {
        LOCK(wallet->cs_wallet);
        for (auto& entry : stagedKeys) {
            wallet->mapHybridKeys.emplace(entry.first, std::move(entry.second));
        }
    }
    printf("Hybrid key pool of size %d created successfully\n", nSize);
}

void CWallet::LoadHybridKeys()
{
    if (!fFileBacked) return;

    LOCK(cs_wallet);
    CWalletDB walletdb(strWalletFile);
    std::vector<CHybridKeyDisk> disks;

    if (!walletdb.LoadAllHybridKeys(disks)) {
        printf("WARNING: failed to load hybrid keys from DB\n");
        return;
    }

    for (const auto& disk : disks) {
        if (!LoadHybridKey(this, disk)) {
            printf("WARNING: failed to load hybrid key %s\n",
                   disk.secpPub.GetID().ToString().c_str());
        }
    }
}

// ============================================================================
// HYBRID KEY VALIDATION
// ============================================================================

bool ValidateHybridKey(const CHybridKey& hk)
{
    // ECDSA private/public key must exist
    if (hk.secpPriv.empty())
        return false;

    if (!hk.secpPub.IsValid())
        return false;

    // Phoenixcoin uses compressed public keys only
    if (hk.secpPub.Raw().size() != 33)
        return false;

    // Algorithm string
    if (hk.mldsaAlg != "p384_mldsa65")
        return false;

    // ML-DSA signer
    if (!hk.mldsaSigner)
        return false;

    EVP_PKEY* pkey = hk.mldsaSigner->GetKey();
    if (!pkey)
        return false;

    // Verify ECDSA key pair
    try
    {
        CKey key = hk.GetCKey();

        if (!key.IsValid())
            return false;

        if (key.GetPubKey() != hk.secpPub)
            return false;
    }
    catch (...)
    {
        return false;
    }

    // Creation time
    if (hk.nCreateTime <= 0)
        return false;

    return true;
}
