#include "hybrid_signer.h"
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(
    const uint8_t* data, size_t size) {

    std::vector<uint8_t> in(data, data + size);

    auto s1 = DilithiumSigner::FromSerialized(in);
    auto s2 = DilithiumSigner::FromSerializedV2(in);

    (void)s1;
    (void)s2;
    return 0;
}
