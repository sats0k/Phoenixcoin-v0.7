#include "hybrid_signer.h"
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(
    const uint8_t* data, size_t size) {

    if (size < 1) return 0;

    HybridSigner hs;

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA_65, nullptr);
    if (!ctx) return 0;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) > 0 &&
        EVP_PKEY_keygen(ctx, &pkey) > 0) {
        hs.Add(std::make_unique<DilithiumSigner>(pkey));
    }
    EVP_PKEY_CTX_free(ctx);

    std::vector<uint8_t> msg(data, data + size);
    std::vector<Signature> sigs;
    hs.SignAll(msg, sigs);
    hs.VerifyAll(msg, sigs);
    return 0;
}
