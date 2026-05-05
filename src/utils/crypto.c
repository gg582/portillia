/**
 * @file crypto.c
 * @brief Implementation of cryptographic primitives for Portillia.
 */

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>
#include <portillia/utils/log.h>
#include <portillia/utils/crypto.h>

/**
 * @brief Keccak-256 implementation using SHA3IUF.
 */
#include "sha3.h"
void portillia_crypto_keccak256(const uint8_t *data, size_t len, uint8_t *out) {
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, data, len, out, 32);
}

/**
 * @brief Derive Ethereum address from Secp256k1 public key.
 */
void portillia_crypto_pubkey_to_address(const uint8_t *pubkey, size_t pubkey_len, char *out_addr) {
    uint8_t hash[32];
    portillia_crypto_keccak256(pubkey + 1, pubkey_len - 1, hash);
    
    strcpy(out_addr, "0x");
    for (int i = 12; i < 32; i++) {
        sprintf(out_addr + 2 + (i - 12) * 2, "%02x", hash[i]);
    }
}

/**
 * @brief Derive WireGuard Overlay IPv4 address from public key.
 */
int portillia_crypto_derive_overlay_ipv4(const char *pubkey_b64, char *out_ipv4) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t*)pubkey_b64, strlen(pubkey_b64), hash);

    sprintf(out_ipv4, "100.%d.%d.%d", 
            64 + (hash[0] & 0x3f),
            hash[1],
            1 + (hash[2] % 254));
    return 0;
}

#include <secp256k1.h>
#include <secp256k1_recovery.h>

/**
 * @brief Generates a new Secp256k1 identity using libsecp256k1.
 */
int portillia_crypto_generate_identity(char *out_priv, char *out_addr) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t seckey[32];
    secp256k1_pubkey pubkey;

    // Generate random private key
    do {
        if (RAND_bytes(seckey, 32) != 1) {
            secp256k1_context_destroy(ctx);
            return -1;
        }
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));

    // Derive public key
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Serialize public key (uncompressed for address)
    size_t pub_len = 65;
    uint8_t pub_buf[65];
    secp256k1_ec_pubkey_serialize(ctx, pub_buf, &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    // Derive Address
    portillia_crypto_pubkey_to_address(pub_buf, pub_len, out_addr);

    // Encode private key as hex (simplified)
    for(int i = 0; i < 32; i++) sprintf(out_priv + i*2, "%02x", seckey[i]);

    secp256k1_context_destroy(ctx);
    return 0;
}

/**
 * @brief Recovers Secp256k1 public key from a 65-byte compact signature (r, s, v).
 * @param payload SHA-256 hash of the signed data.
 * @param signature 65-byte compact signature.
 * @param out_pubkey 65-byte buffer for uncompressed public key.
 */
int portillia_crypto_recover_secp256k1_compact(const uint8_t *hash, const uint8_t *signature, int recid, uint8_t *out_pubkey) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_pubkey pubkey;

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, signature, recid)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    if (!secp256k1_ecdsa_recover(ctx, &pubkey, &sig, hash)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    size_t pub_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, out_pubkey, &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    secp256k1_context_destroy(ctx);
    return 0;
}
