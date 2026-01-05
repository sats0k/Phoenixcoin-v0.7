// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "key.h"

/* ----------  Global secp256k1 context ---------- */
static secp256k1_context* g_secp256k1_ctx = [] {
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                    SECP256K1_CONTEXT_VERIFY);
}();

/* ----------  Build EVP_PKEY from raw secret ---------- */
static EVP_PKEY* MakePKeyFromSecret(const uchar* secret, size_t secret_len,
                                    const uchar* pubkey, size_t pubkey_len) {
    if (!secret || secret_len != 32) return nullptr;

    if (pubkey_len != 65 || pubkey[0] != 0x04) return nullptr;

    static OSSL_LIB_CTX* libctx = [] {
        OSSL_LIB_CTX* c = OSSL_LIB_CTX_new();
        OSSL_PROVIDER_load(c, "default");
        OSSL_PROVIDER_load(c, "legacy");
        return c;
    }();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", nullptr);
    if (!ctx) return nullptr;

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    BIGNUM* bn = BN_bin2bn(secret, 32, nullptr);
    if (!bn) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    uchar bn_buf[32];
    BN_bn2binpad(bn, bn_buf, sizeof(bn_buf));
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"secp256k1",
                               0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, bn_buf, sizeof(bn_buf)),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pubkey, 65),
        OSSL_PARAM_END};

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        ERR_print_errors_fp(stderr);
        BN_clear_free(bn);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    BN_clear_free(bn);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* ----------  Recover pubkey from sig ---------- */
CPubKey RecoverPubKey(const uint256& hash, const uchar sig64[64], int recid,
                      bool compressed) {
    secp256k1_ecdsa_recoverable_signature rsig;
    secp256k1_pubkey pub;

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            g_secp256k1_ctx, &rsig, sig64, recid))
        return CPubKey();

    if (!secp256k1_ecdsa_recover(g_secp256k1_ctx, &pub, &rsig,
                                 reinterpret_cast<const uchar*>(&hash)))
        return CPubKey();

    uchar out[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, out, &len, &pub,
                                  SECP256K1_EC_UNCOMPRESSED);
    return CPubKey(std::vector<uchar>(out, out + len));
}

/* ----------  CKey methods ---------- */

void CKey::SetCompressedPubKey() { fCompressedPubKey = true; }

bool CKey::IsNull() const { return !fSet; }
bool CKey::IsCompressed() const { return fCompressedPubKey; }

void CKey::MakeNewKey(bool fCompressed) {
    Reset();

    CSecret secret(32);
    do {
        if (RAND_bytes(secret.data(), 32) != 1)
            throw key_error("RAND_bytes failed");
    } while (!secp256k1_ec_seckey_verify(g_secp256k1_ctx, secret.data()));

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pub, secret.data()))
        throw key_error("Failed to create public key");

    uchar out[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, out, &len, &pub,
                                  SECP256K1_EC_UNCOMPRESSED);
    EVP_PKEY* tmp = MakePKeyFromSecret(secret.data(), secret.size(), out, len);
    if (!tmp) throw key_error("EVP_PKEY creation failed");

    pkey = tmp;
    vchSecret = secret;
    vchPubKey = CPubKey(std::vector<uchar>(out, out + len));
    fCompressedPubKey = fCompressed;
    fSet = true;
}

bool CKey::SetPrivKey(const CPrivKey& vchPrivKey) {
    Reset();

    if (vchPrivKey.size() == 32) {
        CSecret secret(vchPrivKey.begin(), vchPrivKey.end());
        return SetSecret(secret, false);
    }

    const uchar* p = vchPrivKey.data();
    EVP_PKEY* tmp = d2i_AutoPrivateKey(nullptr, &p, vchPrivKey.size());
    if (!tmp) return false;

    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(tmp, nullptr);
    bool ok = vctx && EVP_PKEY_check(vctx) == 1;
    EVP_PKEY_CTX_free(vctx);
    if (!ok) {
        EVP_PKEY_free(tmp);
        return false;
    }

    BIGNUM* bn = nullptr;
    if (!EVP_PKEY_get_bn_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY, &bn)) {
        EVP_PKEY_free(tmp);
        return false;
    }

    CSecret secret(32, 0);
    BN_bn2binpad(bn, secret.data(), 32);
    BN_clear_free(bn);

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pub, secret.data())) {
        EVP_PKEY_free(tmp);
        return false;
    }

    uchar out[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, out, &len, &pub,
                                  SECP256K1_EC_UNCOMPRESSED);

    pkey = tmp;
    vchSecret = secret;
    vchPubKey = CPubKey(std::vector<uchar>(out, out + len));
    fSet = true;
    return true;
}

bool CKey::SetSecret(const CSecret& secret, bool fCompressed) {
    Reset();

    if (secret.size() != 32) return false;
    if (!secp256k1_ec_seckey_verify(g_secp256k1_ctx, secret.data()))
        return false;

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_ctx, &pub, secret.data()))
        return false;

    uchar out[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, out, &len, &pub,
                                  SECP256K1_EC_UNCOMPRESSED);

    EVP_PKEY* tmp = MakePKeyFromSecret(secret.data(), secret.size(), out, len);
    if (!tmp) return false;

    pkey = tmp;
    vchSecret = secret;
    vchPubKey = CPubKey(std::vector<uchar>(out, out + len));
    fCompressedPubKey = fCompressed;
    fSet = true;
    return true;
}

CSecret CKey::GetSecret(bool& fCompressed) const {
    if (!fSet) throw key_error("CKey::GetSecret(): key not set");
    fCompressed = fCompressedPubKey;
    return vchSecret;
}

CPrivKey CKey::GetPrivKey() const {
    if (!fSet) throw key_error("CKey::GetPrivKey(): key not set");
    return CPrivKey(vchSecret.begin(), vchSecret.end());
}

bool CKey::SetPubKey(const CPubKey& vchPubKeyIn) {
    Reset();

    const std::vector<uchar>& pubkey = vchPubKeyIn.vchPubKey;
    const uchar* pub = pubkey.data();
    size_t pub_len = pubkey.size();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) return false;

    EVP_PKEY* tmp = nullptr;

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"secp256k1",
                               0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pub, pub_len),
        OSSL_PARAM_END};

    if (EVP_PKEY_fromdata(ctx, &tmp, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(tmp, nullptr);
    if (!vctx || EVP_PKEY_public_check(vctx) != 1) {
        EVP_PKEY_CTX_free(vctx);
        EVP_PKEY_free(tmp);
        return false;
    }
    EVP_PKEY_CTX_free(vctx);

    pkey = tmp;
    fSet = true;
    vchPubKey = vchPubKeyIn;
    fCompressedPubKey = (pub_len == 33 && (pub[0] == 0x02 || pub[0] == 0x03));

    return true;
}

CPubKey CKey::GetPubKey() const { return vchPubKey; }

/* ---------- Signing ---------- */

bool CKey::Sign(uint256 hash, std::vector<uchar>& sig) const {
    if (!fSet) return false;

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_sign(g_secp256k1_ctx, &signature, hash.begin(),
                              vchSecret.data(), nullptr, nullptr))
        return false;

    secp256k1_ecdsa_signature sig_norm;
    secp256k1_ecdsa_signature_normalize(g_secp256k1_ctx, &sig_norm, &signature);
    signature = sig_norm;

    uchar der[72];
    size_t derlen = sizeof(der);
    secp256k1_ecdsa_signature_serialize_der(g_secp256k1_ctx, der, &derlen,
                                            &signature);
    sig.assign(der, der + derlen);
    return true;
}

bool CKey::SignCompact(const uint256& hash, std::vector<uchar>& vchSig) const {
    uchar privkey[32];
    std::memcpy(privkey, vchSecret.data(), 32);
    vchSig.clear();
    vchSig.resize(65);

    uchar hashData[32];
    std::memcpy(hashData, const_cast<uint256&>(hash).begin(), 32);
    secp256k1_ecdsa_recoverable_signature sig;

    int signResult = secp256k1_ecdsa_sign_recoverable(
        g_secp256k1_ctx, &sig, hashData, privkey,
        secp256k1_nonce_function_rfc6979, nullptr);

    if (signResult != 1) {
        printf("Signing failed with code: %d\n", signResult);
        return false;
    }

    int recid = 0;
    uchar sig64[64];

    secp256k1_ecdsa_recoverable_signature_serialize_compact(
        g_secp256k1_ctx, sig64, &recid, &sig);

    vchSig[0] = 27 + recid + (fCompressedPubKey ? 4 : 0);
    std::memcpy(&vchSig[1], sig64, 64);

    return true;
}

/* ---------- Verification ---------- */

bool CKey::SetCompactSignature(const uint256& hash,
                               const std::vector<uchar>& vchSig) {
    if (vchSig.size() != 65) return false;

    int header = vchSig[0];
    if (header < 27 || header > 34) return false;

    int recid = (header - 27) & 3;

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            g_secp256k1_ctx, &sig, &vchSig[1], recid))
        return false;

    uchar hashData[32];
    std::memcpy(hashData, const_cast<uint256&>(hash).begin(), 32);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(g_secp256k1_ctx, &pubkey, &sig, hashData))
        return false;

    uchar out[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(g_secp256k1_ctx, out, &len, &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED);
    std::vector<uchar> vchPubKey(out, out + len);
    SetPubKey(CPubKey(vchPubKey));

    fSet = true;
    return true;
}

bool CKey::Verify(uint256 hash, const std::vector<uchar>& sig) const {
    secp256k1_pubkey pub;
    std::vector<uchar> pk = vchPubKey.Raw();
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_ctx, &pub, pk.data(), pk.size()))
        return false;

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_der(g_secp256k1_ctx, &signature,
                                             sig.data(), sig.size()))
        return false;

    secp256k1_ecdsa_signature sig_norm;
    secp256k1_ecdsa_signature_normalize(g_secp256k1_ctx, &sig_norm, &signature);
    signature = sig_norm;

    return secp256k1_ecdsa_verify(g_secp256k1_ctx, &signature, hash.begin(),
                                  &pub);
}

bool CKey::VerifyCompact(const uint256& hash,
                         const std::vector<uchar>& vchSig) const {
    CKey recovered;
    if (!recovered.SetCompactSignature(hash, vchSig)) return false;

    return recovered.GetPubKey() == GetPubKey();
}

bool CKey::IsValid() const {
    if (!fSet || !pkey) return false;

    bool fCompr;
    CSecret secret = GetSecret(fCompr);
    CKey key2;
    if (!key2.SetSecret(secret, fCompr)) return false;

    return GetPubKey() == key2.GetPubKey();
}
