// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef KEY_H
#define KEY_H

#include "ecies/ecies.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <cstring>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#include <openssl/ec.h> // for EC_KEY definition
#endif

#include "allocators.h"
#include "serialize.h"
#include "util.h"

// secp160k1
// const unsigned int PRIVATE_KEY_SIZE = 192;
// const unsigned int PUBLIC_KEY_SIZE  = 41;
// const unsigned int SIGNATURE_SIZE   = 48;
//
// secp192k1
// const unsigned int PRIVATE_KEY_SIZE = 222;
// const unsigned int PUBLIC_KEY_SIZE  = 49;
// const unsigned int SIGNATURE_SIZE   = 57;
//
// secp224k1
// const unsigned int PRIVATE_KEY_SIZE = 250;
// const unsigned int PUBLIC_KEY_SIZE  = 57;
// const unsigned int SIGNATURE_SIZE   = 66;
//
// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push

/* ---------- Errors ---------- */

class key_error : public std::runtime_error {
   public:
    explicit key_error(const std::string &str) : std::runtime_error(str) {}
};

/* ---------- Key identifiers ---------- */

class CKeyID : public uint160 {
   public:
    CKeyID() : uint160(0) {}
    CKeyID(const uint160 &in) : uint160(in) {}
};

class CScriptID : public uint160 {
   public:
    CScriptID() : uint160(0) {}
    CScriptID(const uint160 &in) : uint160(in) {}
};

/* ---------- Public key ---------- */

class CPubKey {
   private:
    EVP_PKEY *pkey;
    std::vector<uchar> vchPubKey;
    friend class CKey;

   public:
    EVP_PKEY* GetEVPPubKey() const;
    CPubKey() {}
    CPubKey(const std::vector<uchar> &vchPubKeyIn)
        : vchPubKey(vchPubKeyIn) {}
    friend bool operator==(const CPubKey &a, const CPubKey &b) {
        return a.vchPubKey == b.vchPubKey;
    }
    friend bool operator!=(const CPubKey &a, const CPubKey &b) {
        return a.vchPubKey != b.vchPubKey;
    }
    friend bool operator<(const CPubKey &a, const CPubKey &b) {
        return a.vchPubKey < b.vchPubKey;
    }

    IMPLEMENT_SERIALIZE(READWRITE(vchPubKey);)

    CKeyID GetID() const { return CKeyID(Hash160(vchPubKey)); }

    uint256 GetHash() const { return Hash(vchPubKey.begin(), vchPubKey.end()); }

    bool IsValid() const {
        return((vchPubKey.size() == 33) || (vchPubKey.size() == 65));
    }

    bool IsCompressed() const { return vchPubKey.size() == 33; }

    std::vector<uchar> Raw() const { return vchPubKey; }

    void EncryptData(const std::vector<unsigned char>& plaintext,
    std::vector<unsigned char>& out);
};

/* ---------- Private key types ---------- */

// Serialized private key
typedef std::vector<uchar, secure_allocator<uchar> > CPrivKey;

// Raw 32-byte secret
typedef std::vector<uchar, secure_allocator<uchar> > CSecret;

/* ---------- Private key ---------- */

class CKey {
   private:
    CSecret vchSecret;
    CPubKey vchPubKey;

   protected:
    EVP_PKEY *pkey;
    bool fSet;
    bool fCompressedPubKey;

    void SetCompressedPubKey();

   public:
    EVP_PKEY* GetEVPPrivKey() const;
    CKey() : pkey(nullptr), fSet(false), fCompressedPubKey(false) {}
    ~CKey() { Reset(); }

    void Reset() {
        if (pkey) EVP_PKEY_free(pkey);
        pkey = nullptr;
        fSet = false;
    }
    bool IsNull() const;
    bool IsCompressed() const;
    void MakeNewKey(bool fCompressed);
    bool SetPrivKey(const CPrivKey &vchPrivKey);
    bool SetSecret(const CSecret &vchSecret, bool fCompressed = false);
    CSecret GetSecret(bool &fCompressed) const;
    CPrivKey GetPrivKey() const;
    bool SetPubKey(const CPubKey &vchPubKeyIn);
    CPubKey GetPubKey() const;
    bool Sign(const uint256 hash, std::vector<uchar> &vchSig) const;
    bool SignCompact(const uint256 &hash,
                     std::vector<uchar> &vchSig) const;
    bool SetCompactSignature(const uint256 &hash,
                             const std::vector<uchar> &vchSig);
    bool Verify(const uint256 hash, const std::vector<uchar> &vchSig) const;
    bool VerifyCompact(const uint256 &hash,
                       const std::vector<uchar> &vchSig) const;
    bool IsValid() const;

    void DecryptData(const std::vector<unsigned char>& enc,
    std::vector<unsigned char>& out);

};

#endif /* KEY_H */
