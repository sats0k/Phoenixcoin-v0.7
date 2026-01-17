#include "hybrid_signer.h"

extern "C" int LLVMFuzzerTestOneInput(
    const uint8_t* data, size_t size) {

    std::vector<uint8_t> input(data, data + size);
    std::vector<uint8_t> password = {'f','u','z','z'};

    auto signer =
        DilithiumSigner::FromEncryptedSerialized(password, input);

    if (signer) {
        auto pub = signer->GetPublicKey();
        (void)pub;
    }
    return 0;
}
