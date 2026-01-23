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
// CHybridKeyDisk methods
// -----------------------------
void CHybridKeyDisk::ComputeChecksum()
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << nVersion << nCreateTime
       << secpPriv << secpPub
       << mldsaAlg;

    ::WriteCompactSize(ss, mldsaPrivKey.size());
    if (!mldsaPrivKey.empty())
        ss.write((const char*)&mldsaPrivKey[0], mldsaPrivKey.size());

    hashChecksum = Hash(ss.begin(), ss.end());
}

bool CHybridKeyDisk::CheckChecksum() const
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << nVersion << nCreateTime
       << secpPriv << secpPub
       << mldsaAlg;

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

    // Serialize MLDSA private key to DER
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
    // Generate secp256k1 key
    CKey key;
    key.MakeNewKey(true);  // compressed
    hk.secpPriv = key.GetPrivKey();
    hk.secpPub  = key.GetPubKey();

    // Generate MLDSA key
    hk.mldsaSigner = MLDSASigner::GenerateNew();
    if (!hk.mldsaSigner)
        throw std::runtime_error("Failed to generate MLDSA key");

    // Set creation time
    hk.nCreateTime = GetTime();
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

    EVP_PKEY_up_ref(pkey); // OpenSSL 3 safe
    return std::make_unique<MLDSASigner>(pkey);
}

std::unique_ptr<MLDSASigner> MLDSASigner::FromSeed(
    const std::vector<uint8_t>& seed,
    const CKeyID& keyid,
    const std::string& alg)
{
    const char* algo = "p384_mldsa65";

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, algo, nullptr);
    if (!ctx) {
        printf("EVP_PKEY_CTX_new_from_name failed for %s\n", algo);
        ERR_print_errors_fp(stdout);
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("EVP_PKEY_keygen_init failed\n");
        ERR_print_errors_fp(stdout);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("EVP_PKEY_keygen failed for key %s\n", keyid.ToString().c_str());
        ERR_print_errors_fp(stdout);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return std::make_unique<MLDSASigner>(pkey);
}

// -----------------------------
// Wallet integration
// -----------------------------
bool LoadHybridKey(CWallet* wallet, const CHybridKeyDisk& disk)
{
    LOCK(wallet->cs_wallet);

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

    // Deserialize secp key
    CHybridKey mem;
    mem.nCreateTime = disk.nCreateTime;
    mem.secpPriv    = disk.secpPriv;
    mem.secpPub     = disk.secpPub;
    mem.mldsaAlg    = disk.mldsaAlg;

    CKey key;
    if (!key.SetPrivKey(mem.secpPriv) || !key.IsValid()) {
        printf("FAIL: invalid secp key\n");
        return false;
    }
    key.SetPubKey(mem.secpPub);

    // Load MLDSA key
    const unsigned char* p = disk.mldsaPrivKey.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, disk.mldsaPrivKey.size());
    if (!pkey) {
        ERR_print_errors_fp(stdout);
        printf("FAIL: MLDSA private key decode failed\n");
        return false;
    }

    auto signer = std::make_unique<MLDSASigner>(pkey);
    wallet->mapHybridSigners[mem.GetKeyID()] = std::move(signer);

    printf("Hybrid key %s loaded successfully\n", mem.GetKeyID().ToString().c_str());
    return true;
}

bool EnsureFirstHybridKey(CWallet* wallet)
{
    LOCK(wallet->cs_wallet);

    if (wallet->vchDefaultKey.IsValid())
        return true;

    printf("DEBUG: Creating first hybrid key\n");
    CHybridKey hk;
    GenerateHybridKey(hk);

    CWalletDB walletdb(wallet->strWalletFile);
    CHybridKeyDisk disk = CHybridKeyDisk::FromMemory(hk);

    walletdb.TxnBegin();
    if (!walletdb.WriteHybridKey(hk.GetKeyID(), disk)) {
        printf("ERROR: failed to write hybrid key\n");
        walletdb.TxnAbort();
        return false;
    }
    walletdb.TxnCommit();

    if (!LoadHybridKey(wallet, disk)) {
        printf("ERROR: failed to load hybrid key into memory\n");
        return false;
    }

    wallet->vchDefaultKey = hk.secpPub;
    wallet->SetDefaultKey(hk.secpPub);
    wallet->SetAddressBookName(hk.secpPub.GetID(), "");

    printf("DEBUG: First hybrid key created successfully\n");
    return true;
}

void NewHybridKeyPool(CWallet* wallet, int nSize)
{
    CWalletDB walletdb(wallet->strWalletFile);
    LOCK(wallet->cs_wallet);

    walletdb.TxnBegin();
    for (int i = 0; i < nSize; ++i) {
        CHybridKey hk;
        GenerateHybridKey(hk);

        CHybridKeyDisk disk = CHybridKeyDisk::FromMemory(hk);
        if (!walletdb.WriteHybridKey(hk.GetKeyID(), disk)) {
            printf("ERROR: failed to write hybrid key to DB\n");
            walletdb.TxnAbort();
            return;
        }

        wallet->mapHybridKeys[hk.GetKeyID()] = std::move(hk);
    }
    walletdb.TxnCommit();

    printf("Hybrid key pool of size %d created successfully\n", nSize);
}
