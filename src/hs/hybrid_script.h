/*
 * Copyright (c) 2026 sats0k
 * Distributed under the MIT/X11 software licence, see the accompanying
 * file LICENCE or http://opensource.org/license/mit
 *
 * HYBRID SCRIPT SYSTEM - Post-Quantum Signature Verification
 * OP_CHECKHYBRIDSIG, OP_CHECKHYBRIDSIGVERIFY, OP_CHECKMULTIHYBRIDSIG
 */

#ifndef HYBRID_SCRIPT_H
#define HYBRID_SCRIPT_H

#include <vector>
#include <cstring>
#include <stdexcept>

// ============================================================================
// HYBRID SCRIPT CONSTANTS - SIZES
// ============================================================================

/**
 * ML-DSA-65 Public Key Size
 * NIST FIPS 204 compliance: ML-DSA-65 produces public keys of 1952 bytes
 */
static constexpr size_t ML_DSA_65_PUBKEY_SIZE = 1952;

/**
 * ML-DSA-65 Signature Size
 * NIST FIPS 204 compliance: ML-DSA-65 signatures are 3310 bytes
 */
static constexpr size_t ML_DSA_65_SIG_SIZE = 3310;

/**
 * ECDSA secp256k1 Public Key Size (Compressed)
 * Standard compressed format: 33 bytes (1 byte prefix + 32 bytes X coordinate)
 */
static constexpr size_t ECDSA_PUBKEY_SIZE = 33;

/**
 * ECDSA secp256k1 Signature Size
 * DER-encoded: typically 71-72 bytes (variable, including sighash byte)
 */
static constexpr size_t ECDSA_SIG_MAX_SIZE = 73;

/**
 * Hybrid Public Key Total Size
 * ECDSA pubkey (33 bytes) + ML-DSA pubkey (1952 bytes) = 1985 bytes
 */
static constexpr size_t HYBRID_PUBKEY_SIZE = ECDSA_PUBKEY_SIZE + ML_DSA_65_PUBKEY_SIZE;

/**
 * Hybrid Signature Total Size
 * ECDSA sig (max 73 bytes) + ML-DSA sig (3310 bytes) = max 3383 bytes
 */
static constexpr size_t HYBRID_SIG_MAX_SIZE = ECDSA_SIG_MAX_SIZE + ML_DSA_65_SIG_SIZE;

// ============================================================================
// HYBRID SCRIPT OPCODES
// ============================================================================

/**
 * OP_CHECKHYBRIDSIG (0xbc)
 * Verifies single hybrid signature (ECDSA + ML-DSA)
 * Stack: sig_ecdsa sig_mldsa pubkey_ecdsa pubkey_mldsa -> bool
 */
//static constexpr unsigned char OP_CHECKHYBRIDSIG = 0xbc;

/**
 * OP_CHECKHYBRIDSIGVERIFY (0xbd)
 * Verifies single hybrid signature, fails if invalid
 * Stack: sig_ecdsa sig_mldsa pubkey_ecdsa pubkey_mldsa -> (fails or empty)
 */
//static constexpr unsigned char OP_CHECKHYBRIDSIGVERIFY = 0xbd;

/**
 * OP_CHECKMULTIHYBRIDSIG (0xbe)
 * Verifies M-of-N hybrid multisignature
 * Stack: sig_1 ... sig_m m pubkey_1 ... pubkey_n n -> bool
 */
//static constexpr unsigned char OP_CHECKMULTIHYBRIDSIG = 0xbe;

// ============================================================================
// HYBRID SCRIPT HELPER FUNCTIONS
// ============================================================================

/**
 * Validate hybrid public key format
 * 
 * @param hybridPubKey Combined ECDSA (33 bytes) + ML-DSA (1952 bytes) public key
 * @return true if size is exactly 1985 bytes, false otherwise
 */
inline bool ValidateHybridPubKey(const std::vector<unsigned char>& hybridPubKey) {
    return hybridPubKey.size() == HYBRID_PUBKEY_SIZE;
}

/**
 * Split hybrid public key into ECDSA and ML-DSA components
 * 
 * @param hybridPubKey Combined ECDSA + ML-DSA public key (1985 bytes)
 * @param ecdsaPubKey Output: ECDSA secp256k1 public key (33 bytes)
 * @param mldsaPubKey Output: ML-DSA-65 public key (1952 bytes)
 * @return true if split successful, false if input size invalid
 */
inline bool SplitHybridPubKey(
    const std::vector<unsigned char>& hybridPubKey,
    std::vector<unsigned char>& ecdsaPubKey,
    std::vector<unsigned char>& mldsaPubKey
) {
    if (hybridPubKey.size() != HYBRID_PUBKEY_SIZE) {
        return false;
    }
    
    ecdsaPubKey.assign(
        hybridPubKey.begin(),
        hybridPubKey.begin() + ECDSA_PUBKEY_SIZE
    );
    
    mldsaPubKey.assign(
        hybridPubKey.begin() + ECDSA_PUBKEY_SIZE,
        hybridPubKey.end()
    );
    
    return true;
}

/**
 * Combine ECDSA and ML-DSA public keys into hybrid format
 * 
 * @param ecdsaPubKey ECDSA secp256k1 public key (33 bytes)
 * @param mldsaPubKey ML-DSA-65 public key (1952 bytes)
 * @param hybridPubKey Output: Combined hybrid public key
 * @return true if sizes are valid and combining succeeds
 */
inline bool CombineHybridPubKey(
    const std::vector<unsigned char>& ecdsaPubKey,
    const std::vector<unsigned char>& mldsaPubKey,
    std::vector<unsigned char>& hybridPubKey
) {
    if (ecdsaPubKey.size() != ECDSA_PUBKEY_SIZE ||
        mldsaPubKey.size() != ML_DSA_65_PUBKEY_SIZE) {
        return false;
    }
    
    hybridPubKey.clear();
    hybridPubKey.insert(hybridPubKey.end(), ecdsaPubKey.begin(), ecdsaPubKey.end());
    hybridPubKey.insert(hybridPubKey.end(), mldsaPubKey.begin(), mldsaPubKey.end());
    
    return true;
}

/**
 * Validate hybrid signature format (basic size checks)
 * 
 * @param hybridSig Combined ECDSA + ML-DSA signature
 * @return true if size is within valid range, false otherwise
 */
inline bool ValidateHybridSignature(const std::vector<unsigned char>& hybridSig) {
    // Minimum: smallest ECDSA sig (71 bytes) + ML-DSA sig (3310 bytes) = 3381 bytes
    // Maximum: largest ECDSA sig (73 bytes) + ML-DSA sig (3310 bytes) = 3383 bytes
    return hybridSig.size() >= (71 + ML_DSA_65_SIG_SIZE) &&
           hybridSig.size() <= HYBRID_SIG_MAX_SIZE;
}

/**
 * Split hybrid signature into ECDSA and ML-DSA components
 * 
 * Assumes ECDSA signature is prefix (variable 71-73 bytes) and ML-DSA is suffix.
 * Detects ECDSA signature end by DER encoding length field.
 * 
 * @param hybridSig Combined signature
 * @param ecdsaSig Output: ECDSA DER-encoded signature (71-73 bytes)
 * @param mldsaSig Output: ML-DSA signature (3310 bytes)
 * @return true if split successful, false if format invalid
 */
inline bool SplitHybridSignature(
    const std::vector<unsigned char>& hybridSig,
    std::vector<unsigned char>& ecdsaSig,
    std::vector<unsigned char>& mldsaSig
) {
    if (hybridSig.size() < (71 + ML_DSA_65_SIG_SIZE)) {
        return false;
    }
    
    // ECDSA DER signature format: 0x30 [length] [r] [s]
    // Length field at position 1, total length = 2 + length value
    if (hybridSig.empty() || hybridSig[0] != 0x30) {
        return false;  // Not DER format
    }
    
    if (hybridSig.size() < 2) {
        return false;  // Too short for DER header
    }
    
    unsigned char derLen = hybridSig[1];
    size_t ecdsaSigLen = 2 + derLen;  // 0x30 + length byte + content
    
    if (ecdsaSigLen < 71 || ecdsaSigLen > 73) {
        return false;  // Invalid ECDSA signature length
    }
    
    if (ecdsaSigLen + ML_DSA_65_SIG_SIZE != hybridSig.size()) {
        return false;  // Size mismatch
    }
    
    ecdsaSig.assign(hybridSig.begin(), hybridSig.begin() + ecdsaSigLen);
    mldsaSig.assign(hybridSig.begin() + ecdsaSigLen, hybridSig.end());
    
    return true;
}

/**
 * Combine ECDSA and ML-DSA signatures into hybrid format
 * 
 * @param ecdsaSig ECDSA DER-encoded signature (71-73 bytes)
 * @param mldsaSig ML-DSA signature (3310 bytes)
 * @param hybridSig Output: Combined hybrid signature
 * @return true if sizes are valid and combining succeeds
 */
inline bool CombineHybridSignature(
    const std::vector<unsigned char>& ecdsaSig,
    const std::vector<unsigned char>& mldsaSig,
    std::vector<unsigned char>& hybridSig
) {
    if ((ecdsaSig.size() < 71 || ecdsaSig.size() > 73) ||
        mldsaSig.size() != ML_DSA_65_SIG_SIZE) {
        return false;
    }
    
    hybridSig.clear();
    hybridSig.insert(hybridSig.end(), ecdsaSig.begin(), ecdsaSig.end());
    hybridSig.insert(hybridSig.end(), mldsaSig.begin(), mldsaSig.end());
    
    return true;
}

/**
 * Validate sigop count for hybrid signatures
 * 
 * OP_CHECKHYBRIDSIG counts as 2 sigops (ECDSA + ML-DSA)
 * OP_CHECKMULTIHYBRIDSIG counts as 2 × (required signatures)
 * 
 * @param sigopCount Current accumulated sigop count
 * @param maxAllowed Maximum allowed sigops per block (default: 20000)
 * @return true if adding hybrid verification won't exceed limit
 */
inline bool ValidateSigopCount(unsigned int sigopCount, unsigned int maxAllowed = 20000) {
    return sigopCount <= maxAllowed;
}

#endif // HYBRID_SCRIPT_H
