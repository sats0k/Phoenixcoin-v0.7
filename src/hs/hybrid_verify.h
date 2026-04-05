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
 * @param mldsaSig    ML-DSA-65 signature in binary format (4595 bytes)
 * @param mldsaPubKey ML-DSA-65 public key in DER format (1312 bytes)
 * @param msg         Message to verify (typically 32-byte sighash)
 * @return true if signature verifies, false if invalid or error
 * 
 * @note Uses SHA-256 internally (per FIPS 204 ML-DSA-65)
 * @note Requires OpenSSL 3.2 or later for EVP_PKEY_ML_DSA_65 support
 */
inline bool VerifyMLDSA(
    const std::vector<unsigned char>& mldsaSig,
    const std::vector<unsigned char>& mldsaPubKey,
    const std::vector<unsigned char>& msg
)
{
    // ---- Input validation ----
    if (mldsaSig.size() != ML_DSA_65_SIG_SIZE) {
        return false;
    }

    if (mldsaPubKey.size() != ML_DSA_65_PUBKEY_SIZE) {
        return false;
    }

    if (msg.empty() || msg.size() > 1024) {
        return false;
    }

    // ---- Deserialize ML-DSA public key (DER format) ----
    // OpenSSL 3.2+ uses EVP_PKEY_ML_DSA_65 for ML-DSA-65 keys
    EVP_PKEY* pkey = NULL;
    const unsigned char* pubkey_ptr = mldsaPubKey.data();
    
    pkey = d2i_PublicKey(
        EVP_PKEY_ML_DSA_65,  // Correct OpenSSL 3.2 constant
        &pkey,
        &pubkey_ptr,
        (long)mldsaPubKey.size()
    );

    if (!pkey) {
        // Failed to deserialize public key
        return false;
    }

    // ---- Create EVP_MD_CTX for verification ----
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    // ---- Initialize digest verification (SHA-256) ----
    const EVP_MD* md = EVP_sha256();
    if (!md) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    if (1 != EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey)) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // ---- Feed message data ----
    if (1 != EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size())) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // ---- Verify signature ----
    // Returns: 1 if signature is valid, 0 if invalid, -1 if error
    int result = EVP_DigestVerifyFinal(ctx, mldsaSig.data(), mldsaSig.size());

    // ---- Cleanup ----
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Return true only if result == 1 (valid signature)
    return (result == 1);
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
 * @param vchPubKeyML   ML-DSA-65 public key (1312 bytes, DER format)
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
    int nHashType
)
{
    // ---- Input size validation ----
    // ECDSA: 71-73 bytes (DER-encoded signature)
    if (vchSigEC.size() < 71 || vchSigEC.size() > 73) {
        return false;
    }

    // ML-DSA-65: exactly 4595 bytes (per FIPS 204)
    if (vchSigML.size() != ML_DSA_65_SIG_SIZE) {
        return false;
    }

    // ECDSA pubkey: 33 bytes (compressed secp256k1)
    if (vchPubKeyEC.size() != ECDSA_PUBKEY_SIZE) {
        return false;
    }

    // ML-DSA-65 pubkey: 1312 bytes (per FIPS 204)
    if (vchPubKeyML.size() != ML_DSA_65_PUBKEY_SIZE) {
        return false;
    }

    // ---- Step 1: Verify ECDSA signature ----
    // Uses classical secp256k1 ECDSA verification
    // This is faster to evaluate and can early-exit if invalid
    bool ecdsaValid = CheckSig(
        vchSigEC,
        vchPubKeyEC,
        scriptCode,
        txTo,
        nIn,
        nHashType
    );
    
    if (!ecdsaValid) {
        return false;  // Classical signature failed, reject
    }

    // ---- Step 2: Compute sighash and build ML-DSA message ----
    // Get the transaction signature hash (deterministic)
    uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType);
    
    // Build domain-separated message (32-byte sighash)
    // This ensures ML-DSA signs a different message than ECDSA,
    // preventing signature substitution attacks across algorithms
    std::vector<unsigned char> msg;
    BuildHybridMessage(sighash, msg);

    // Verify message was constructed correctly
    if (msg.size() != 32) {
        return false;
    }

    // ---- Step 3: Verify ML-DSA-65 signature ----
    // Uses NIST FIPS 204 ML-DSA-65 for post-quantum security
    bool mldsaValid = VerifyMLDSA(vchSigML, vchPubKeyML, msg);

    if (!mldsaValid) {
        return false;  // Post-quantum signature failed, reject
    }

    // ---- Both signatures verified successfully ----
    return true;
}

#endif // HYBRID_VERIFY_H
