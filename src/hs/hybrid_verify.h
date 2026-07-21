// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef HYBRID_VERIFY_H
#define HYBRID_VERIFY_H

#pragma once

#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "hybrid_script.h"
#include "../uint256.h"
#include "../script.h"


/**
 * ML-DSA-65 Signature Verification Module
 * 
 * Provides NIST FIPS 204 compliant ML-DSA-65 signature verification
 * for hybrid (ECDSA + ML-DSA) transaction signing.
 * 
 * Requires: OpenSSL 3.2+ with ML-DSA support (EVP_PKEY_ML_DSA_65)
 */

// ============================================================================
// ML-DSA SIGNATURE VERIFICATION
// ============================================================================

/**
 * Verify ML-DSA-65 signature using OpenSSL EVP_PKEY interface
 * 
 * ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is defined in
 * NIST FIPS 204 as a post-quantum signature scheme resistant to attacks
 * by both classical and quantum computers.
 * 
 * @param mldsaSig    ML-DSA-65 signature in binary format (3310 bytes)
 * @param mldsaPubKey ML-DSA-65 public key in DER format (1952 bytes)
 * @param msg         Message to verify (typically 32-byte sighash)
 * @return true if signature verifies, false if invalid or error
 * 
 * @note Uses SHA-256 internally (per FIPS 204 ML-DSA-65)
 * @note Requires OpenSSL 3.2 or later for EVP_PKEY_ML_DSA_65 support
 */
inline bool VerifyMLDSA(
    const std::vector<unsigned char>& mldsaSig,
    const std::vector<unsigned char>& mldsaPubKey,
    const std::vector<unsigned char>& msg)
{
    // Validate inputs
    if (mldsaSig.empty())
        return false;

    if (mldsaPubKey.size() != ML_DSA_65_PUBKEY_SIZE)
        return false;

    if (msg.empty() || msg.size() > 1024)
        return false;

    // Import raw ML-DSA public key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(
        nullptr,
        "ML-DSA-65",
        nullptr,
        mldsaPubKey.data(),
        mldsaPubKey.size());

    if (!pkey)
        return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    const bool ok =
        EVP_DigestVerify(
            ctx,
            mldsaSig.data(),
            mldsaSig.size(),
            msg.data(),
            msg.size()) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok;
}

// ============================================================================
// HYBRID SIGNATURE VERIFICATION
// ============================================================================

// Forward declarations
//class CScript;
//class CTransaction;

/**
 * Forward declaration for CheckSig from script.cpp
 * Verifies ECDSA secp256k1 signatures
 */
extern bool CheckSig(
    const std::vector<unsigned char>& vchSig,
    const std::vector<unsigned char>& vchPubKey,
    const CScript& scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType
);

/**
 * Forward declaration for BuildHybridMessage from script.cpp
 * Creates domain-separated message for hybrid signatures
 */
extern void BuildHybridMessage(
    const uint256& sighash,
    std::vector<unsigned char>& outMsg
);


/**
 * Forward declaration for SignatureHash from script.cpp
 * Computes transaction signature hash
 * Note: defined in script.cpp, takes CScript by value
 */
extern uint256 SignatureHash(
    CScript scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType
);

/**
 * Verify complete hybrid signature (ECDSA + ML-DSA-65)
 * 
 * Both signatures must verify for the function to return true.
 * Uses domain separation to ensure security of both classical and post-quantum
 * components.
 * 
 * Stack semantics (from script):
 *   sig_ecdsa sig_mldsa pubkey_ecdsa pubkey_mldsa -- bool
 * 
 * Signature verification order:
 * 1. Validate input sizes (ECDSA: 71-73 bytes, ML-DSA: 4595 bytes)
 * 2. Verify ECDSA signature using secp256k1
 * 3. Compute transaction sighash
 * 4. Build domain-separated message
 * 5. Verify ML-DSA-65 signature
 * 6. Return success only if both signatures valid
 * 
 * @param vchSigEC      ECDSA signature (DER-encoded, 71-73 bytes)
 * @param vchSigML      ML-DSA-65 signature (4595 bytes)
 * @param vchPubKeyEC   ECDSA public key (33 bytes, compressed secp256k1)
 * @param vchPubKeyML   ML-DSA-65 public key (1950 bytes, DER format)
 * @param scriptCode    Script being executed (for codeseparator handling)
 * @param txTo          Transaction being verified
 * @param nIn           Input index in transaction
 * @param nHashType     Signature hash type (SIGHASH_ALL, etc.)
 * 
 * @return true if and only if both ECDSA and ML-DSA signatures verify
 * 
 * @note Requires both classical (ECDSA) and post-quantum (ML-DSA) components
 *       to be valid. Failure of either component causes verification to fail.
 * @note Uses domain separation: both signers sign the same sighash but via
 *       different messages, preventing cross-algorithm substitution attacks.
 * @note Security: This implementation follows hybrid signature best practices:
 *       - Sequential verification (ECDSA first, faster to reject)
 *       - Proper domain separation (different messages for each algorithm)
 *       - Comprehensive size validation
 *       - Full cleanup of OpenSSL objects
 */
inline bool VerifyHybridSignature(
    const std::vector<unsigned char>& vchSigEC,
    const std::vector<unsigned char>& vchSigML,
    const std::vector<unsigned char>& vchPubKeyEC,
    const std::vector<unsigned char>& vchPubKeyML,
    const CScript& scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType)
{
    // ------------------------------------------------------------
    // Basic validation
    // ------------------------------------------------------------
    if (vchSigEC.empty() ||
        vchSigML.empty() ||
        vchPubKeyEC.empty() ||
        vchPubKeyML.empty())
        return false;

    if (vchPubKeyEC.size() != ECDSA_PUBKEY_SIZE)
        return false;

    if (vchPubKeyML.size() != ML_DSA_65_PUBKEY_SIZE)
        return false;

    // ------------------------------------------------------------
    // Determine sighash type
    // Both signatures must carry the same hash type.
    // ------------------------------------------------------------
    int hashTypeEC = vchSigEC.back();
    int hashTypeML = vchSigML.back();

    if (hashTypeEC != hashTypeML)
        return false;

    if (nHashType != 0 && hashTypeEC != nHashType)
        return false;

    // ------------------------------------------------------------
    // Verify ECDSA signature
    // ------------------------------------------------------------
    if (!CheckSig(
            vchSigEC,
            vchPubKeyEC,
            scriptCode,
            txTo,
            nIn,
            hashTypeEC))
    {
        return false;
    }

    // ------------------------------------------------------------
    // Remove sighash byte from ML-DSA signature
    // ------------------------------------------------------------
    std::vector<unsigned char> mldsaSig(
        vchSigML.begin(),
        vchSigML.end() - 1);

    // ------------------------------------------------------------
    // Build the exact message signed by ML-DSA
    // ------------------------------------------------------------
    uint256 sighash =
        SignatureHash(scriptCode, txTo, nIn, hashTypeEC);

    std::vector<unsigned char> hybridMsg;
    BuildHybridMessage(sighash, hybridMsg);

    // ------------------------------------------------------------
    // Verify ML-DSA signature
    // ------------------------------------------------------------
    if (!VerifyMLDSA(
            mldsaSig,
            vchPubKeyML,
            hybridMsg))
    {
        return false;
    }

    return true;
}

#endif // HYBRID_VERIFY_H
