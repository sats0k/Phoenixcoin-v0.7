#include "hs/hybrid_signer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

EVP_PKEY* generate_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA_65, nullptr);
    if (!ctx) return nullptr;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;  // Caller is responsible for freeing this key
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    const size_t split = size / 2;

    if (split == 0 || split == size) return 0;

    std::vector<uint8_t> msg(data, data + split);
    std::vector<uint8_t> mutation(data + split, data + size);

    // Generate key once outside the fuzz loop
    static EVP_PKEY* pkey = generate_key();
    if (!pkey) return 0;

    // Create signer with the existing key
    auto signer = std::make_unique<MLDSASigner>(pkey);

    // Since MLDSASigner takes its own EVP_PKEY reference, no need to free pkey
    // here If MLDSASigner does not take ownership, you may need to manage pkey
    // lifetime accordingly

    HybridSigner hs;
    hs.Add(std::move(signer));

    std::vector<Signature> sigs;
    if (!hs.SignAll(msg, sigs)) return 0;

    if (!sigs.empty() && !sigs[0].bytes.empty()) {
        for (size_t i = 0; i < mutation.size(); ++i) {
            const size_t pos = i % sigs[0].bytes.size();
            sigs[0].bytes[pos] ^= mutation[i];
        }
    }

    (void)hs.VerifyAll(msg, sigs);

    return 0;
}
