// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <string>

#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <openssl/err.h>      // ERR_get_error, ERR_error_string_n

#include "base58.h"
#include "wallet.h"
#include "rpcmain.h"
#include "hs/wallethybrid.h"

using namespace json_spirit;
using namespace std;

extern CWallet *pwalletMain;

class CTxDump {
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx *ptx;
    int nOut;
    CTxDump(CWalletTx *ptx = NULL, int nOut = -1) {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};


Value importprivkey(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3)) {
        string msg = "importprivkey <key> [label] [rescan]\n"
          "Adds a private <key> to the wallet in the format of RPC dumpprivkey.\n"
          "[label] specifies an in-wallet text label, empty by default.\n" 
          "[rescan] allows to rescan the block chain, true by default.";
        throw(runtime_error(msg));
    }

    string strSecret = params[0].get_str();
    string strLabel = "";
    if(params.size() > 1)
      strLabel = params[1].get_str();

    bool fRescan = true;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CCoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, true);
    CKeyID vchAddress = key.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        pwalletMain->UpdateTimeFirstKey();

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return(Value::null);
}


Value importaddress(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3)) {
        string msg = "importaddress <address> [label] [rescan]\n"
          "Adds a watch only (unspendable) P2PKH <address> to the wallet.\n"
          "Pubkey hash or script in hex may be specified instead of the <address>.\n"
          "[label] specifies an in-wallet text label, empty by default.\n" 
          "[rescan] allows to rescan the block chain, true by default.";
        throw(runtime_error(msg));
    }

    string strLabel = "";
    if(params.size() > 1)
      strLabel = params[1].get_str();

    bool fRescan = false;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CScript script;
    CCoinAddress addr;

    if(IsHex(params[0].get_str())) {
        std::vector<uchar> vchScriptPubKey(ParseHex(params[0].get_str()));
        std::string strTemp;
        if(vchScriptPubKey.size() == 20) {
            /* 20-byte pubkey hash assumed;
             * <pubKeyHash> = RIPEMD160(SHA256(pubKey))
             * Example using OpenSSL:
             * echo -n <pubKey> | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -rmd160
             * Convert to 25-byte script:
             * OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG */
            strTemp = std::string(vchScriptPubKey.begin(), vchScriptPubKey.end());
            const uchar begin[] = { 0x76, 0xA9, 0x14 };
            const uchar end[] = { 0x88, 0xAC };
            vchScriptPubKey.insert(vchScriptPubKey.begin(), begin, begin + 3);
            vchScriptPubKey.insert(vchScriptPubKey.end(), end, end + 2);
        } else if(vchScriptPubKey.size() == 25) {
            /* Copy the public key hash */
            strTemp = params[0].get_str().substr(6, 40);
        } else {
            throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid pubkey hash or script"));
        }
        script = CScript(vchScriptPubKey.begin(), vchScriptPubKey.end());
        /* Insert the Base58 prefix */
        char prefix[2];
        if(fTestNet) prefix[0] = PUBKEY_ADDRESS_TEST_PREFIX;
        else prefix[0] = PUBKEY_ADDRESS_PREFIX;
        prefix[1] = 0x00;
        strTemp.insert(0, prefix);
        /* Convert and encode */
        std::vector<uchar> vchTemp(ParseHex(strTemp));
        addr = CCoinAddress(EncodeBase58Check(vchTemp));
    } else {
        CKeyID keyID;
        addr = CCoinAddress(params[0].get_str());
        if(!addr.GetKeyID(keyID))
          throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address"));
        script = GetScriptForPubKeyHash(keyID);
    }

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
          throw(JSONRPCError(RPC_WALLET_ERROR, "The private key is already in the wallet"));

        if(pwalletMain->HaveWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "The address is being watched already"));

        pwalletMain->MarkDirty();

        if(addr.IsValid())
          pwalletMain->SetAddressBookName(addr.Get(), strLabel);

        if(!pwalletMain->AddWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "Failed to add the address to the wallet"));

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }

    }

    return(Value::null);
}


Value importpubkey(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3)) {
        string msg =  "importpubkey <key> [label] [rescan]\n"
          "Adds a watch only (unspendable) public <key> in hex to the wallet.\n"
          "[label] specifies an in-wallet text label, empty by default.\n" 
          "[rescan] allows to rescan the block chain, true by default.";
        throw(runtime_error(msg));
    }

    string strLabel = "";
    if(params.size() > 1)
      strLabel = params[1].get_str();

    bool fRescan = false;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CScript script;
    CCoinAddress addr(params[0].get_str());

    if(!IsHex(params[0].get_str()))
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Hex string expected for public key"));

    CPubKey pubKey(std::vector<uchar> (ParseHex(params[0].get_str())));
    if(!pubKey.IsValid())
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key"));

    CKeyID keyID = pubKey.GetID();
    addr = CCoinAddress(keyID);
    script = GetScriptForPubKeyHash(keyID);

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
          throw(JSONRPCError(RPC_WALLET_ERROR, "The private key is already in the wallet"));

        if(pwalletMain->HaveWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "The public key is being watched already"));

        pwalletMain->MarkDirty();

        if(addr.IsValid())
          pwalletMain->SetAddressBookName(addr.Get(), strLabel);

        if(!pwalletMain->AddWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "Failed to add the public key to the wallet"));

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }

    }

    return(Value::null);
}


Value importwallet(const Array &params, bool fHelp) {

    if(fHelp || (params.size() != 1)) {
        string msg = "importwallet <file>\n"
          "Imports key pairs from a <file> generated by RPC dumpwallet.\n"
          "The file name may be specified with a directory path.";
        throw(runtime_error(msg));
    }

    EnsureWalletIsUnlocked();

    boost::filesystem::ifstream file;
    boost::filesystem::path pathImportFile = params[0].get_str().c_str();
    if(!pathImportFile.is_absolute()) pathImportFile = GetDataDir(true) / pathImportFile;
    if(!boost::filesystem::exists(pathImportFile))
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "The file with wallet keys doesn't exist"));
    file.open(pathImportFile, std::ios_base::in);
    if(!file.good())
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open the file with wallet keys"));
    file.close();

    if(!ImportWallet(pwalletMain, pathImportFile.string().c_str()))
      throw(JSONRPCError(RPC_WALLET_ERROR, "Failed while importing keys to the wallet"));

    return(Value::null);
}


Value dumpprivkey(const Array &params, bool fHelp) {

    if(fHelp || (params.size() != 1)) {
        string msg = "dumpprivkey <address>\n"
          "Reveals the private key corresponding to an <address>.";
        throw(runtime_error(msg));
    }

    string strAddress = params[0].get_str();
    CCoinAddress address;
    if(!address.SetString(strAddress))
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Phoenixcoin address"));
    CKeyID keyID;
    if(!address.GetKeyID(keyID))
      throw(JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key"));
    CSecret vchSecret;
    bool fCompressed;
    if(!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw(JSONRPCError(RPC_WALLET_ERROR,
          "Private key for address " + strAddress + " is not known"));
    }
    return(CCoinSecret(vchSecret, fCompressed).ToString());
}


Value dumpwallet(const Array &params, bool fHelp) {

    if(fHelp || (params.size() != 1)) {
        string msg = "dumpwallet <file>\n"
          "Dumps key pairs to a <file> in a human readable format.\n"
          "The file name may be specified with a directory path.";
        throw(runtime_error(msg));
    }

    EnsureWalletIsUnlocked();

    boost::filesystem::ofstream file;
    boost::filesystem::path pathDumpFile = params[0].get_str().c_str();
    if(!pathDumpFile.is_absolute()) pathDumpFile = GetDataDir(true) / pathDumpFile;
    if(boost::filesystem::exists(pathDumpFile))
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "The file for wallet keys exists already"));
    file.open(pathDumpFile, std::ios_base::out);
    if(!file.good())
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "Cannot create the file for wallet keys"));
    file.close();

    if(!ExportWallet(pwalletMain, pathDumpFile.string().c_str()))
      throw(JSONRPCError(RPC_WALLET_ERROR, "Failed while exporting keys from the wallet"));

    return(Value::null);
}

Value dumphybridkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        string msg =
            "dumphybridkey <address>\n"
            "Reveals the hybrid private key (secp256k1 + MLDSA) for <address>.";
        throw runtime_error(msg);
    }

    string strAddress = params[0].get_str();
    CCoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");

    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");

    LOCK(pwalletMain->cs_wallet);

    // ---- secp256k1 (same as dumpprivkey) ----
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Private key for address " + strAddress + " is not known");
    }

    string wif = CCoinSecret(vchSecret, fCompressed).ToString();

    // ---- hybrid MLDSA ----
    if (!pwalletMain->EnsureHybridKey(keyID))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create hybrid key");

    auto it = pwalletMain->mapHybridSigners.find(keyID);
    if (it == pwalletMain->mapHybridSigners.end())
        throw JSONRPCError(RPC_WALLET_ERROR, "No hybrid key for this address");

    MLDSASigner* signer = it->second.get();
    EVP_PKEY* pkey = signer->GetKey();
    if (!pkey)
        throw JSONRPCError(RPC_WALLET_ERROR, "MLDSA key missing");

    // Serialize MLDSA private key to DER
    unsigned char* buf = NULL;
    int len = i2d_PrivateKey(pkey, &buf);
    if (len <= 0 || !buf)
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize MLDSA key");

    vector<unsigned char> der(buf, buf + len);
    OPENSSL_free(buf);

    string der_b64 = EncodeBase64(der.data(), der.size());

    Object result;
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("secp_wif", wif));
    result.push_back(Pair("mldsa_alg", "p384_mldsa65"));
    result.push_back(Pair("mldsa_priv_der_b64", der_b64));
    result.push_back(Pair("hybridkey_disk_version", HYBRIDKEY_DISK_VERSION));
    result.push_back(Pair("hybrid_sig_version", HYBRID_SIG_VERSION));

    return result;
}

Value gethybridaddress(const Array& params, bool fHelp) {
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "gethybridaddress [label]\n"
            "Returns a new hybrid (quantum-resistant) Bitcoin address for "
            "receiving payments.\n"
            "Each address uses both secp256k1 (ECDSA) and ML-DSA-65 "
            "(lattice-based) cryptography.\n"
            "If [label] is specified, that label is assigned to the "
            "address.\n");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with "
                           "walletpassphrase first.");

    // Top up key pool before generating
    if (!pwalletMain->TopUpKeyPool())
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: Wallet key pool top-up failed.");

    // Generate new hybrid key
    CHybridKey hybridKey;
    try {
        GenerateHybridKey(hybridKey);
        if (!ValidateHybridKey(hybridKey))
            throw std::runtime_error("Generated invalid hybrid key");
    } catch (std::exception& e) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            string("Error: Failed to generate hybrid key: ") + e.what());
    }

    CKeyID keyID = hybridKey.GetKeyID();
    CPubKey ecdsaPubKey = hybridKey.secpPub;

    // Store in wallet - move semantics since we can't copy
    {
        LOCK(pwalletMain->cs_wallet);

        pwalletMain->mapHybridKeys.emplace(keyID, std::move(hybridKey));

        auto it = pwalletMain->mapHybridKeys.find(keyID);
        if (it == pwalletMain->mapHybridKeys.end())
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to store hybrid key.");

        std::unique_ptr<MLDSASigner> signer = GetSignerFromKey(it->second);

        if (!signer)
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "Failed to clone MLDSA signer.");

        pwalletMain->mapHybridSigners.emplace(keyID, std::move(signer));

        // Persist to database
        CWalletDB walletdb(pwalletMain->strWalletFile);
        CHybridKeyDisk diskKey = CHybridKeyDisk::FromMemory(it->second);
        if (!walletdb.WriteHybridKey(keyID, diskKey))
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Error: Failed to write hybrid key to database.");
    }

    // Build hybrid script - use ECDSA pubkey for address
    CScript scriptPubKey;
    scriptPubKey << ecdsaPubKey << OP_CHECKSIG;

    // Generate address from script - convert script to vector for Hash160
    vector<unsigned char> scriptVec(scriptPubKey.begin(), scriptPubKey.end());
    uint160 scriptHash = Hash160(scriptVec);
    CScriptID scriptID(scriptHash);
    CCoinAddress address(scriptID);
    string strAddress = address.ToString();

    // Set label if provided
    if (params.size() > 0) {
        string strLabel = params[0].get_str();
        {
            LOCK(pwalletMain->cs_wallet);
            pwalletMain->SetHybridAddressBookName(keyID, strLabel);

            // Persist label
            CWalletDB walletdb(pwalletMain->strWalletFile);
            walletdb.WriteHybridAddressEntry(keyID, strLabel);
        }
    }

    return strAddress;
}

Value listhybridaddresses(const Array& params, bool fHelp) {
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listhybridaddresses [includeempty]\n"
            "Returns a list of all hybrid (quantum-resistant) addresses in the "
            "wallet.\n"
            "\nArguments:\n"
            "1. includeempty (boolean, optional, default=false) - Include "
            "addresses with no labels\n"
            "\nResult is array of objects with: address, label, pubkey_ecdsa, "
            "created\n");

    bool fIncludeEmpty = true;
    if (params.size() > 0) fIncludeEmpty = params[0].get_bool();

    Array result;
    {
        LOCK(pwalletMain->cs_wallet);

        for (map<CKeyID, CHybridKey>::iterator it =
                 pwalletMain->mapHybridKeys.begin();
             it != pwalletMain->mapHybridKeys.end(); ++it) {
            const CKeyID& keyID = it->first;
            const CHybridKey& hybridKey = it->second;

            // Get label if exists
            string strLabel = "";
            if (pwalletMain->mapHybridAddressBook.count(keyID))
                strLabel = pwalletMain->mapHybridAddressBook[keyID].strLabel;

            if (!fIncludeEmpty && strLabel.empty())
                continue;  // Skip unlabeled addresses if not requested

            // Build address from script
            CScript scriptPubKey;
            scriptPubKey << hybridKey.secpPub << OP_CHECKSIG;
            vector<unsigned char> scriptVec(scriptPubKey.begin(),
                                            scriptPubKey.end());
            uint160 scriptHash = Hash160(scriptVec);
            CScriptID scriptID(scriptHash);
            CCoinAddress address(scriptID);

            // Build result object
            Object obj;
            obj.push_back(Pair("address", address.ToString()));
            obj.push_back(Pair("label", strLabel));
            obj.push_back(
                Pair("pubkey_ecdsa", HexStr(hybridKey.secpPub.Raw())));
            obj.push_back(Pair("created", (int64_t)hybridKey.nCreateTime));

            result.push_back(obj);
        }
    }

    return result;
}

Value gethybridkey(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gethybridkey \"address\"\n"
            "Returns the public key components for the given hybrid address.\n"
            "Reveals both ECDSA and ML-DSA-65 public key components (not "
            "private keys).\n"
            "\nArguments: 1. address (string, required) - The hybrid address\n"
            "\nResult object contains: address, pubkey_ecdsa, "
            "pubkey_mldsa_b64, algorithm_mldsa, created, label\n"
            "Note: Use 'dumphybridkey' to get private keys.\n");

    string strAddress = params[0].get_str();
    CCoinAddress address(strAddress);

    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid Bitcoin address");

    if (!address.IsScript())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Address is not a script address");

    CScriptID scriptID = get<CScriptID>(address.Get());

    // Find hybrid key in wallet
    const CHybridKey* pHybridKey = nullptr;
    CKeyID foundKeyID;
    {
        LOCK(pwalletMain->cs_wallet);

        for (map<CKeyID, CHybridKey>::const_iterator it =
                 pwalletMain->mapHybridKeys.begin();
             it != pwalletMain->mapHybridKeys.end(); ++it) {
            CScript testScript;
            testScript << it->second.secpPub << OP_CHECKSIG;
            vector<unsigned char> scriptVec(testScript.begin(),
                                            testScript.end());
            uint160 testHash = Hash160(scriptVec);
            CScriptID testID(testHash);

            if (testID == scriptID) {
                pHybridKey = &(it->second);
                foundKeyID = it->first;
                break;
            }
        }
    }

    if (!pHybridKey)
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            "Address does not correspond to a hybrid key in this wallet");

    // Get MLDSA public key from signer
    string strMldsaPubB64;
    printf("Hybrid signers: %u\n",
           (unsigned)pwalletMain->mapHybridSigners.size());

    if (!pwalletMain->mapHybridSigners.count(foundKeyID)) {
        printf("Signer NOT found\n");
    } else {
        printf("Signer found\n");

        MLDSASigner* signer = pHybridKey->mldsaSigner.get();

        if (!signer) {
            printf("Signer pointer NULL\n");
        } else {
            EVP_PKEY* pkey = signer->GetKey();

            printf("EVP_PKEY=%p\n", (void*)pkey);

            if (!pkey) {
                printf("GetKey() returned NULL\n");
            } else {
                std::vector<uint8_t> pub = signer->GetPublicKey();

                if (!pub.empty())
                    strMldsaPubB64 = EncodeBase64(pub.data(), pub.size());
            }
        }
    }

    // Build response
    Object result;
    result.push_back(Pair("address", strAddress));
    result.push_back(Pair("pubkey_ecdsa", HexStr(pHybridKey->secpPub.Raw())));
    result.push_back(Pair("pubkey_mldsa_b64", strMldsaPubB64));
    result.push_back(Pair("algorithm_mldsa", pHybridKey->mldsaAlg));
    result.push_back(Pair("created", (int64_t)pHybridKey->nCreateTime));

    // Add label if exists
    {
        LOCK(pwalletMain->cs_wallet);
        if (pwalletMain->mapHybridAddressBook.count(foundKeyID))
            result.push_back(
                Pair("label",
                     pwalletMain->mapHybridAddressBook[foundKeyID].strLabel));
    }

    return result;
}
