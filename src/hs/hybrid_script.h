/*
 * Copyright (c) 2026 sats0k
 * Distributed under the MIT/X11 software licence, see the accompanying
 * file LICENCE or http://opensource.org/license/mit
 */

#ifndef HYBRID_SCRIPT_H
#define HYBRID_SCRIPT_H

#include <vector>
#include <cstring>
#include <stdexcept>

// ============================================================================
// HYBRID CRYPTOGRAPHIC CONSTANTS
// ============================================================================

/**
 * ML-DSA-65 raw public key size in bytes.
 */
static constexpr size_t ML_DSA_65_PUBKEY_SIZE = 1952;

/**
 * ML-DSA-65 raw signature size in bytes.
 */
static constexpr size_t ML_DSA_65_SIG_SIZE = 3310;

/**
 * Compressed secp256k1 public key size in bytes.
 */
static constexpr size_t ECDSA_PUBKEY_SIZE = 33;

/**
 * Maximum DER-encoded ECDSA signature size including the sighash type byte.
 */
static constexpr size_t ECDSA_SIG_MAX_SIZE = 73;

#endif // HYBRID_SCRIPT_H
