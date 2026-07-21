// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "../wallet.h"
#include "../walletdb.h"
#include "../util.h"
#include "wallethybrid.h"

// ============================================================================
// HYBRID ADDRESS BOOK IMPLEMENTATION
// ============================================================================

bool CWallet::SetHybridAddressBookName(const CHybridKeyID& keyID, const std::string& strName, const std::string& strPurpose)
{
    LOCK(cs_wallet);
    
    // Check if key exists in hybrid keys
    if (mapHybridKeys.find(keyID) == mapHybridKeys.end()) {
        printf("ERROR: SetHybridAddressBookName: Hybrid key %s not found\n", keyID.ToString().c_str());
        return false;
    }
    
    // Create address entry
    CHybridAddressEntry entry(strName, strPurpose);
    entry.nCreateTime = GetTime();
    
    // Update in-memory map
    mapHybridAddressBook[keyID] = entry;
    
    // Persist to database if wallet is backed
    if (fFileBacked) {
        CWalletDB walletdb(strWalletFile);
        if (!walletdb.WriteHybridAddressEntry(keyID, entry)) {
            printf("ERROR: SetHybridAddressBookName: Failed to write to database\n");
            return false;
        }
    }
    
    printf("Hybrid address %s labeled as '%s'\n", keyID.ToString().c_str(), strName.c_str());
    return true;
}

bool CWallet::GetHybridAddressBookName(const CHybridKeyID& keyID, std::string& strNameOut) const
{
    LOCK(cs_wallet);
    
    auto it = mapHybridAddressBook.find(keyID);
    if (it == mapHybridAddressBook.end()) {
        return false;
    }
    
    strNameOut = it->second.strLabel;
    return true;
}

bool CWallet::DelHybridAddressBookName(const CHybridKeyID& keyID)
{
    LOCK(cs_wallet);
    
    // Remove from memory
    auto it = mapHybridAddressBook.find(keyID);
    if (it == mapHybridAddressBook.end()) {
        return false;
    }
    
    mapHybridAddressBook.erase(it);
    
    // Remove from database if backed
    if (fFileBacked) {
        CWalletDB walletdb(strWalletFile);
        if (!walletdb.EraseHybridAddressEntry(keyID)) {
            printf("WARNING: DelHybridAddressBookName: Failed to erase from database\n");
            return false;
        }
    }
    
    printf("Hybrid address %s removed from address book\n", keyID.ToString().c_str());
    return true;
}

std::vector<std::pair<CKeyID, std::string>> CWallet::ListHybridAddresses() const
{
    LOCK(cs_wallet);
    
    std::vector<std::pair<CKeyID, std::string>> result;
    
    for (const auto& entry : mapHybridAddressBook) {
        result.push_back(std::make_pair(entry.first, entry.second.strLabel));
    }
    
    return result;
}

void CWallet::LoadHybridAddressBook()
{
    if (!fFileBacked) return;
    
    LOCK(cs_wallet);
    
    CWalletDB walletdb(strWalletFile);
    if (!walletdb.LoadAllHybridAddresses(mapHybridAddressBook)) {
        printf("WARNING: Failed to load hybrid address book from database\n");
        return;
    }
    
    printf("Loaded %zu hybrid addresses from address book\n", mapHybridAddressBook.size());
}
