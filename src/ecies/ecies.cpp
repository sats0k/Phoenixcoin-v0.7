// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

#include <cstdio>
#include <cstring>

#include "ecies.h"

static constexpr size_t PUBKEY_LEN = 65;  // uncompressed secp256k1
static constexpr size_t NONCE_LEN = 12;   // GCM standard
static constexpr size_t TAG_LEN = 16;
static constexpr size_t KEY_LEN = 32;

/* ---------------- ECDH helper ---------------- */

static bool ECDH_Derive(EVP_PKEY* privkey, EVP_PKEY* pubkey,
                        unsigned char out[32]) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    if (!ctx) return false;

    size_t outlen = 32;

    bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_derive_set_peer(ctx, pubkey) == 1 &&
              EVP_PKEY_derive(ctx, out, &outlen) == 1 && outlen == 32;

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/* ---------------- HKDF ---------------- */

static bool HKDF_SHA256(const unsigned char* secret, size_t secret_len,
                        const unsigned char* salt, size_t salt_len,
                        unsigned char out[32]) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) return false;

    size_t outlen = 32;

    bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_len) == 1 &&
              EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char*)"ecies-v1",
                                          8) == 1 &&
              EVP_PKEY_derive(ctx, out, &outlen) == 1 && outlen == 32;

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/* ---------------- Encrypt ---------------- */

bool ECIES_Encrypt(EVP_PKEY* recipient_pubkey,
                   const std::vector<unsigned char>& plaintext,
                   std::vector<unsigned char>& out) {
    if (!recipient_pubkey || plaintext.empty()) return false;

    /* 1. Generate ephemeral key */
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(recipient_pubkey, nullptr);
    if (!kctx) return false;

    EVP_PKEY* eph = nullptr;
    if (EVP_PKEY_keygen_init(kctx) != 1 || EVP_PKEY_keygen(kctx, &eph) != 1) {
        EVP_PKEY_CTX_free(kctx);
        return false;
    }
    EVP_PKEY_CTX_free(kctx);

    /* 2. ECDH */
    unsigned char shared[32];
    if (!ECDH_Derive(eph, recipient_pubkey, shared)) {
        EVP_PKEY_free(eph);
        return false;
    }

    /* 3. Serialize ephemeral pubkey */
    unsigned char eph_pub[PUBKEY_LEN];
    size_t eph_len = PUBKEY_LEN;

    if (EVP_PKEY_get_octet_string_param(eph, OSSL_PKEY_PARAM_PUB_KEY, eph_pub,
                                        sizeof(eph_pub), &eph_len) != 1 ||
        eph_len != PUBKEY_LEN) {
        EVP_PKEY_free(eph);
        return false;
    }

    /* 4. Derive AEAD key */
    unsigned char aead_key[32];
    if (!HKDF_SHA256(shared, sizeof(shared), eph_pub, PUBKEY_LEN, aead_key)) {
        EVP_PKEY_free(eph);
        return false;
    }

    /* 5. Nonce */
    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        EVP_PKEY_free(eph);
        return false;
    }

    /* 6. Encrypt (AES-256-GCM) */
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if (!cctx) {
        EVP_PKEY_free(eph);
        return false;
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len = 0, ct_len = 0;

    EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);
    EVP_EncryptInit_ex(cctx, nullptr, nullptr, aead_key, nonce);

    /* AAD: bind ephemeral pubkey + nonce */
    EVP_EncryptUpdate(cctx, nullptr, &len, eph_pub, PUBKEY_LEN);
    EVP_EncryptUpdate(cctx, nullptr, &len, nonce, NONCE_LEN);

    EVP_EncryptUpdate(cctx, ciphertext.data(), &len, plaintext.data(),
                      plaintext.size());
    ct_len = len;

    EVP_EncryptFinal_ex(cctx, ciphertext.data() + len, &len);
    ct_len += len;

    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

    EVP_CIPHER_CTX_free(cctx);
    EVP_PKEY_free(eph);

    /* 7. Serialize output */
    out.clear();
    out.reserve(PUBKEY_LEN + NONCE_LEN + ct_len + TAG_LEN);

    out.insert(out.end(), eph_pub, eph_pub + PUBKEY_LEN);
    out.insert(out.end(), nonce, nonce + NONCE_LEN);
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin() + ct_len);
    out.insert(out.end(), tag, tag + TAG_LEN);

    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(aead_key, sizeof(aead_key));
    return true;
}

/* ---------------- Decrypt ---------------- */

bool ECIES_Decrypt(EVP_PKEY* recipient_privkey,
                   const std::vector<unsigned char>& enc,
                   std::vector<unsigned char>& out) {
    if (!recipient_privkey || enc.size() < PUBKEY_LEN + NONCE_LEN + TAG_LEN)
        return false;

    const unsigned char* p = enc.data();

    const unsigned char* eph_pub = p;
    p += PUBKEY_LEN;

    const unsigned char* nonce = p;
    p += NONCE_LEN;

    size_t ct_len = enc.size() - PUBKEY_LEN - NONCE_LEN - TAG_LEN;
    const unsigned char* ciphertext = p;
    const unsigned char* tag = p + ct_len;

    /* 1. Load ephemeral pubkey */
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) return false;

    EVP_PKEY* eph = nullptr;

    if (EVP_PKEY_fromdata_init(ctx) != 1) return false;

    OSSL_PARAM params[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                  (char*)"secp256k1", 0),
                           OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                   (void*)eph_pub, PUBKEY_LEN),
                           OSSL_PARAM_END};

    if (EVP_PKEY_fromdata(ctx, &eph, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    /* 2. ECDH */
    unsigned char shared[32];
    if (!ECDH_Derive(recipient_privkey, eph, shared)) {
        EVP_PKEY_free(eph);
        return false;
    }

    /* 3. Derive key */
    unsigned char aead_key[32];
    if (!HKDF_SHA256(shared, sizeof(shared), eph_pub, PUBKEY_LEN, aead_key)) {
        EVP_PKEY_free(eph);
        return false;
    }

    /* 4. Decrypt */
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    if (!cctx) {
        EVP_PKEY_free(eph);
        return false;
    }

    out.resize(ct_len);
    int len = 0;

    EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);
    EVP_DecryptInit_ex(cctx, nullptr, nullptr, aead_key, nonce);

    EVP_DecryptUpdate(cctx, nullptr, &len, eph_pub, PUBKEY_LEN);
    EVP_DecryptUpdate(cctx, nullptr, &len, nonce, NONCE_LEN);

    EVP_DecryptUpdate(cctx, out.data(), &len, ciphertext, ct_len);
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag);

    bool ok = EVP_DecryptFinal_ex(cctx, out.data() + len, &len) == 1;

    EVP_CIPHER_CTX_free(cctx);
    EVP_PKEY_free(eph);

    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(aead_key, sizeof(aead_key));

    return ok;
}

/* ------------------------------------------------ */
/* High-level wrappers                              */
/* ------------------------------------------------ */

static void set_error(char* err, size_t len, const char* msg) {
    if (err && len) std::snprintf(err, len, "%s", msg);
}

ByteVector ecies_encrypt(const ecies_ctx_t* ctx, const unsigned char* data,
                         size_t length, char* error, size_t error_len) {
    if (!ctx || !ctx->recipient_pubkey || !data || length == 0) {
        set_error(error, error_len, "Invalid arguments");
        return {};
    }

    ByteVector plaintext(data, data + length);
    ByteVector encrypted;

    if (!ECIES_Encrypt(ctx->recipient_pubkey, plaintext, encrypted)) {
        set_error(error, error_len, "ECIES encryption failed");
        return {};
    }

    return encrypted;
}

ByteVector ecies_decrypt(const ecies_ctx_t* ctx, const ByteVector& cryptex,
                         char* error, size_t error_len) {
    if (!ctx || !ctx->recipient_privkey || cryptex.empty()) {
        set_error(error, error_len, "Invalid arguments");
        return {};
    }

    ByteVector decrypted;
    if (!ECIES_Decrypt(ctx->recipient_privkey, cryptex, decrypted)) {
        set_error(error, error_len, "ECIES decryption failed");
        return {};
    }

    return decrypted;
}

