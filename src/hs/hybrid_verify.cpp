// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "hybrid_verify.h"

// This file provides the inline implementations in hybrid_verify.h
// No additional implementation needed - all functions are inline.
// The external declarations (CheckSig, BuildHybridMessage, SignatureHash)
// are provided by script.cpp and script.h.

/*
 * ============================================================================
 * COMPILATION NOTES
 * ============================================================================
 *
 * This module requires:
 * 1. OpenSSL 3.2 or later (for EVP_PKEY_ML_DSA_65 support)
 * 2. Compiler with C++11 or later
 * 3. Link against OpenSSL crypto library
 *
 * To compile with this module:
 *   g++ -std=c++11 -I/path/to/openssl/include \
 *       -L/path/to/openssl/lib -lcrypto -o program ...
 *
 * ============================================================================
 */
