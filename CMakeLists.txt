cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(HybridSigner LANGUAGES CXX C)

# ---------------------------------------------------------------------------
# C++ standard
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# OpenSSL (ML-DSA requires OpenSSL 3.2+)
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

if (NOT OpenSSL_VERSION VERSION_GREATER_EQUAL "3.2.0")
    message(FATAL_ERROR
        "OpenSSL >= 3.2.0 required for ML-DSA support, found ${OpenSSL_VERSION}")
endif()

# ---------------------------------------------------------------------------
# secp256k1 (vendored, production)
# ---------------------------------------------------------------------------
add_library(secp256k1 STATIC
    src/secp256k1/src/secp256k1.c
)

set_target_properties(secp256k1 PROPERTIES
    LINKER_LANGUAGE C
)

target_include_directories(secp256k1
    PUBLIC
        src/secp256k1/include
        src/secp256k1/src
)

target_compile_definitions(secp256k1
    PRIVATE
        ENABLE_MODULE_ECDSA
        ENABLE_MODULE_RECOVERY
)

target_compile_options(secp256k1
    PRIVATE
        -fno-strict-aliasing
)

# ---------------------------------------------------------------------------
# Phoenixcoin crypto (REAL, minimal)
# ---------------------------------------------------------------------------
add_library(phoenixcoin_crypto STATIC
    src/key.cpp
)

target_include_directories(phoenixcoin_crypto
    PUBLIC
        src
)

target_link_libraries(phoenixcoin_crypto
    PUBLIC
        secp256k1
        OpenSSL::Crypto
)

# ---------------------------------------------------------------------------
# Hybrid signer (production)
# ---------------------------------------------------------------------------
add_library(hybrid_signer STATIC
    src/hs/hybrid_signer.cpp
    src/hs/hybrid_signer.h
)

target_include_directories(hybrid_signer
    PUBLIC
        src
)

target_link_libraries(hybrid_signer
    PUBLIC
        phoenixcoin_crypto
        OpenSSL::Crypto
)

# ---------------------------------------------------------------------------
# Fuzzers
# ---------------------------------------------------------------------------
#function(add_fuzzer name source)
#    add_executable(${name} ${source})

#    target_link_libraries(${name}
#        PRIVATE
#            hybrid_signer
#            OpenSSL::Crypto
#    )

#    if (SANITIZER_FLAGS AND NOT MSVC)
#        target_compile_options(${name} PRIVATE ${SANITIZER_FLAGS} -fno-exceptions -fno-rtti)
#        target_link_options(${name} PRIVATE ${SANITIZER_FLAGS} -fsanitize=fuzzer)
#    endif()
#endfunction()

#add_fuzzer(fuzz_dilithium_deserialize src/test/fuzz/fuzz_dilithium_deserialize.cpp)
#add_fuzzer(fuzz_encrypted_keys        src/test/fuzz/fuzz_encrypted_keys.cpp)
#add_fuzzer(fuzz_hybrid_verify         src/test/fuzz/fuzz_hybrid_verify.cpp)
