#include <boost/test/unit_test.hpp>

#include <cstring>

#include "main.h"
#include "script.h"
#include "hs/hybrid_signer.h"

extern uint256 SignatureHash(CScript scriptCode,
                            const CTransaction& txTo,
                            unsigned int nIn,
                            int nHashType);

BOOST_AUTO_TEST_CASE(hybrid_multisig_sighash_types)
{
    /*
     * Regression test for OP_CHECKMULTIHYBRIDSIG sighash handling.
     *
     * The signatures are created with nHashType == 0 at script
     * verification time, so the opcode must obtain the sighash type
     * from the final byte of the signatures themselves.
     *
     * Test:
     *   SIGHASH_ALL
     *   SIGHASH_NONE
     *   SIGHASH_SINGLE
     *   SIGHASH_ALL | SIGHASH_ANYONECANPAY
     */

    CKey ecdsaKey;
    ecdsaKey.MakeNewKey(true);

    std::unique_ptr<MLDSASigner> mldsaSigner =
        MLDSASigner::GenerateNew();

    BOOST_REQUIRE(mldsaSigner);

    const std::vector<unsigned char> ecdsaPub =
        ecdsaKey.GetPubKey().Raw();

    const std::vector<unsigned char> mldsaPub =
        mldsaSigner->GetPublicKey();

    BOOST_REQUIRE_EQUAL(ecdsaPub.size(), 33U);
    BOOST_REQUIRE_EQUAL(mldsaPub.size(), 1952U);

    /*
     * Build the 1-of-1 hybrid multisig script explicitly.
     *
     * The OP_CHECKMULTIHYBRIDSIG implementation expects the ECDSA
     * and ML-DSA public keys as separate stack items.
     */
    CScript scriptPubKey;
    scriptPubKey
        << OP_1
        << ecdsaPub
        << mldsaPub
        << OP_1
        << OP_CHECKMULTIHYBRIDSIG;

    /*
     * Transaction with one input and two outputs.
     *
     * Two outputs are important so SIGHASH_SINGLE at input 0 has a
     * corresponding output.
     */
    CTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(2);

    tx.vin[0].prevout.n = 0;
    tx.vin[0].prevout.hash = uint256(1);

    tx.vout[0].nValue = 100;
    tx.vout[1].nValue = 200;

    const int hashTypes[] = {
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY
    };

    for (size_t testIndex = 0;
         testIndex < sizeof(hashTypes) / sizeof(hashTypes[0]);
         ++testIndex) {

        const int hashType = hashTypes[testIndex];

        /*
         * Compute exactly the sighash that the consensus opcode
         * must use.
         */
        uint256 sighash =
            SignatureHash(scriptPubKey, tx, 0, hashType);

        /*
         * ECDSA component.
         */
        std::vector<unsigned char> sigEC;

        BOOST_REQUIRE(
            ecdsaKey.Sign(sighash, sigEC));

        sigEC.push_back((unsigned char)hashType);

        /*
         * ML-DSA signs the domain-separated canonical sighash preimage.
         * This must exactly match OP_CHECKMULTIHYBRIDSIG verification.
         */
        std::vector<unsigned char> sighash_preimage;

        BOOST_REQUIRE(
            ConstructSignatureHashPreimage(
                scriptPubKey,
                tx,
                0,
                hashType,
                sighash_preimage));

        std::vector<unsigned char> hybridMsg =
            BuildHybridMessage(sighash_preimage);

        std::vector<unsigned char> sigML;

        BOOST_REQUIRE(
            mldsaSigner->Sign(hybridMsg, sigML));

        sigML.push_back((unsigned char)hashType);

        /*
         * ScriptSig:
         *
         *   <ECDSA signature>
         *   <ML-DSA signature>
         *
         * The scriptPubKey then supplies:
         *
         *   1
         *   <ECDSA pubkey>
         *   <ML-DSA pubkey>
         *   1
         *   OP_CHECKMULTIHYBRIDSIG
         */
        CScript scriptSig;
        scriptSig
            << sigEC
            << sigML;

        /*
         * IMPORTANT:
         *
         * nHashType is deliberately ZERO here.
         *
         * This forces OP_CHECKMULTIHYBRIDSIG to obtain the actual
         * sighash type from the signature's final byte.
         *
         * The old implementation fails this regression because it
         * precomputed SignatureHash(..., 0).
         */
        BOOST_CHECK_MESSAGE(
            VerifyScript(
                scriptSig,
                scriptPubKey,
                tx,
                0,
                true,
                0),
            strprintf(
                "OP_CHECKMULTIHYBRIDSIG failed for sighash type 0x%02x",
                hashType));
    }
}
