#!/usr/bin/env python3
import numpy as np
import torch
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# =====================================================================
# Constants — MUST match C++
# =====================================================================
PASSWORD = b"correct horse battery staple"
AAD = b"HYBK\x01"

# =====================================================================
# Generic loader
# =====================================================================
def load_bin(path, device):
    return torch.tensor(
        np.fromfile(path, dtype=np.uint8),
        dtype=torch.uint8,
        device=device
    )

# =====================================================================
# secp256k1
# =====================================================================
def load_secp256k1(device):
    return {
        "priv": load_bin("secp256k1_priv.bin", device),
        "pub":  load_bin("secp256k1_pub.bin", device),
        "sig":  load_bin("secp256k1_sig.bin", device),
    }

# =====================================================================
# Hybrid message
# =====================================================================
def load_hybrid_message(device):
    return load_bin("hybrid_message.bin", device)

# =====================================================================
# ML-DSA-65 serialized private key
# =====================================================================
def load_mldsa65_serialized(device):
    data = np.fromfile("mldsa65_priv_serialized.bin", dtype=np.uint8)
    ptr = 0

    version = data[ptr]
    ptr += 1

    pub_len = (data[ptr] << 8) | data[ptr + 1]
    ptr += 2
    pub = data[ptr:ptr + pub_len]
    ptr += pub_len

    priv_len = (data[ptr] << 8) | data[ptr + 1]
    ptr += 2
    priv = data[ptr:ptr + priv_len]

    return {
        "version": torch.tensor([version], dtype=torch.uint8, device=device),
        "pub": torch.tensor(pub, dtype=torch.uint8, device=device),
        "priv": torch.tensor(priv, dtype=torch.uint8, device=device),
    }

# =====================================================================
# ML-DSA-65 encrypted private key
# =====================================================================
def load_mldsa65_encrypted(device):
    data = np.fromfile("mldsa65_priv_enc.bin", dtype=np.uint8)

    magic = data[0:4]
    version = data[4]
    salt = data[5:21]          # 16 bytes
    nonce = data[21:33]        # 12 bytes
    ciphertext = data[33:-16]
    tag = data[-16:]

    return {
        "magic": torch.tensor(magic, dtype=torch.uint8, device=device),
        "version": torch.tensor([version], dtype=torch.uint8, device=device),
        "salt": torch.tensor(salt, dtype=torch.uint8, device=device),
        "nonce": torch.tensor(nonce, dtype=torch.uint8, device=device),
        "ciphertext": torch.tensor(ciphertext, dtype=torch.uint8, device=device),
        "tag": torch.tensor(tag, dtype=torch.uint8, device=device),
    }

# =====================================================================
# AES-256-GCM decrypt (CRITICAL: includes AAD)
# =====================================================================
def aes_gcm_decrypt(enc, device):
    salt = bytes(enc["salt"].cpu().numpy())
    nonce = bytes(enc["nonce"].cpu().numpy())
    ciphertext = bytes(enc["ciphertext"].cpu().numpy())
    tag = bytes(enc["tag"].cpu().numpy())

    key = PBKDF2(
        PASSWORD,
        salt,
        dkLen=32,
        count=200_000,
        hmac_hash_module=SHA256,
    )

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(AAD)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return torch.from_numpy(
        np.frombuffer(plaintext, dtype=np.uint8).copy()
    ).to(device)

# =====================================================================
# Load everything
# =====================================================================
def load_all_vectors(device):
    return {
        "secp256k1": load_secp256k1(device),
        "hybrid_message": load_hybrid_message(device),
        "mldsa65_serialized": load_mldsa65_serialized(device),
        "mldsa65_encrypted": load_mldsa65_encrypted(device),
    }

# =====================================================================
# Harness
# =====================================================================
def hybrid_crypto_harness(vectors, device):
    return {
        "secp256k1": vectors["secp256k1"],
        "hybrid_message": vectors["hybrid_message"],
        "mldsa65_serialized": vectors["mldsa65_serialized"],
        "mldsa65_decrypted_serialized":
            aes_gcm_decrypt(vectors["mldsa65_encrypted"], device),
    }

# =====================================================================
# Main
# =====================================================================
if __name__ == "__main__":
    device = "cuda" if torch.cuda.is_available() else "cpu"
    vectors = load_all_vectors(device)
    results = hybrid_crypto_harness(vectors, device)

    # ------------------------------------------------------------
    # ML-DSA-65 metadata dump
    # ------------------------------------------------------------
    mldsa_ser = vectors["mldsa65_serialized"]
    mldsa_enc = vectors["mldsa65_encrypted"]

    print("mldsa65 serialized version:",
          int(mldsa_ser["version"][0]))

    print("mldsa65 encrypted magic:",
          bytes(mldsa_enc["magic"].cpu().numpy()))

    print("mldsa65 encrypted version:",
          int(mldsa_enc["version"][0]))

    print("mldsa65 encrypted ciphertext len:",
          mldsa_enc["ciphertext"].shape[0])

    print("mldsa65 encrypted tag:",
          mldsa_enc["tag"].cpu().numpy().tobytes().hex())

    print("mldsa65 encrypted salt:",
          mldsa_enc["salt"].cpu().numpy().tobytes().hex())

    print("Device:", device)
    print("secp256k1 priv:", results["secp256k1"]["priv"].shape)
    print("secp256k1 pub:", results["secp256k1"]["pub"].shape)
    print("secp256k1 sig:", results["secp256k1"]["sig"].shape)
    print("hybrid message:", results["hybrid_message"].shape)
    print("ML-DSA-65 pub:", results["mldsa65_serialized"]["pub"].shape)
    print("ML-DSA-65 priv:", results["mldsa65_serialized"]["priv"].shape)
    print("DECRYPTED serialized:",
          results["mldsa65_decrypted_serialized"].shape)
