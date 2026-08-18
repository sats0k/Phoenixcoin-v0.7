#include "hs/hybrid_signer.h"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(
    const uint8_t* data, size_t size) {

    std::vector<uint8_t> in(data, data + size);

    auto s1 = MLDSASigner::FromSerialized(in);
    auto s2 = MLDSASigner::FromSerializedV2(in);

    (void)s1;
    (void)s2;
    return 0;
}
