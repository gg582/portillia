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
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <portillia/utils/log.h>
#include <portillia/utils/crypto.h>
#include "portillia_go_siwe.h"

/**
 * @brief Keccak-256 implementation using SHA3IUF.
 */
#include "sha3.h"
void portillia_crypto_keccak256(const uint8_t *data, size_t len, uint8_t *out) {
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, data, len, out, 32);
}

/**
 * @brief Derive Ethereum address from Secp256k1 public key (EIP-55 checksummed).
 */
void portillia_crypto_pubkey_to_address(const uint8_t *pubkey, size_t pubkey_len, char *out_addr) {
    uint8_t hash[32];
    portillia_crypto_keccak256(pubkey + 1, pubkey_len - 1, hash);
    
    char lower[41] = {0};
    for (int i = 12; i < 32; i++) {
        sprintf(lower + (i - 12) * 2, "%02x", hash[i]);
    }
    
    uint8_t checksum_hash[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, lower, 40, checksum_hash, 32);
    
    strcpy(out_addr, "0x");
    for (int i = 0; i < 40; i++) {
        char c = lower[i];
        if (c >= '0' && c <= '9') {
            out_addr[2 + i] = c;
        } else {
            int nibble = checksum_hash[i / 2];
            if (i % 2 == 0) {
                nibble >>= 4;
            } else {
                nibble &= 0x0f;
            }
            if (nibble > 7) {
                out_addr[2 + i] = c - ('a' - 'A');
            } else {
                out_addr[2 + i] = c;
            }
        }
    }
    out_addr[42] = '\0';
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
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return -1;
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

static int parse_hex_bytes(const char *hex, uint8_t *out, size_t out_len) {
    const char *cur = hex;
    if (!cur || !out) return -1;
    if (cur[0] == '0' && (cur[1] == 'x' || cur[1] == 'X')) cur += 2;
    if (strlen(cur) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int v = 0;
        if (sscanf(cur + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int ethereum_personal_message_hash(const char *message, uint8_t out_hash[32]) {
    if (!message || !out_hash) return -1;

    char prefix[64];
    int prefix_len = snprintf(prefix, sizeof(prefix), "\x19" "Ethereum Signed Message:\n%zu", strlen(message));
    if (prefix_len < 0 || (size_t)prefix_len >= sizeof(prefix)) return -1;

    size_t message_len = strlen(message);
    size_t payload_len = (size_t)prefix_len + message_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) return -1;

    memcpy(payload, prefix, (size_t)prefix_len);
    memcpy(payload + prefix_len, message, message_len);
    portillia_crypto_keccak256(payload, payload_len, out_hash);
    free(payload);
    return 0;
}

int portillia_crypto_derive_address_from_private_key(const char *private_key_hex, char *out_addr, size_t out_addr_len) {
    if (!private_key_hex || !out_addr || out_addr_len < 43) return -1;

    uint8_t seckey[32];
    if (parse_hex_bytes(private_key_hex, seckey, sizeof(seckey)) != 0) return -1;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return -1;

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    size_t uncompressed_len = 65;
    uint8_t uncompressed[65];
    int ok = secp256k1_ec_pubkey_serialize(ctx, uncompressed, &uncompressed_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_context_destroy(ctx);
    if (!ok) return -1;

    portillia_crypto_pubkey_to_address(uncompressed, uncompressed_len, out_addr);
    return 0;
}

int portillia_crypto_sign_siwe_message(const char *siwe_message, const char *private_key_hex, char *out_sig, size_t out_len) {
    if (!siwe_message || !private_key_hex || !out_sig || out_len < 133) return -1;

    uint8_t seckey[32];
    if (parse_hex_bytes(private_key_hex, seckey, sizeof(seckey)) != 0) return -1;

    uint8_t hash[32];
    if (ethereum_personal_message_hash(siwe_message, hash) != 0) return -1;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return -1;

    secp256k1_ecdsa_recoverable_signature sig;
    int recid = 0;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash, seckey, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    uint8_t compact64[64];
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, compact64, &recid, &sig);
    secp256k1_context_destroy(ctx);

    out_sig[0] = '0';
    out_sig[1] = 'x';
    for (int i = 0; i < 64; i++) {
        sprintf(out_sig + 2 + i * 2, "%02x", compact64[i]);
    }
    sprintf(out_sig + 130, "%02x", (uint8_t)(27 + recid));
    out_sig[132] = '\0';
    return 0;
}

bool portillia_crypto_verify_siwe_signature_address(const char *siwe_message, const char *siwe_signature, const char *expected_address) {
    if (!siwe_message || !siwe_signature || !expected_address) return false;
    return PortilliaGoSiweVerify(siwe_message, siwe_signature, expected_address) == 1;
}
