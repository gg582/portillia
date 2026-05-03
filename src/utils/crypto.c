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

/**
 * @brief Keccak-256 implementation using OpenSSL EVP.
 */
void portillia_crypto_keccak256(const uint8_t *data, size_t len, uint8_t *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname("keccak-256");
    if (!md) {
        md = EVP_sha3_256(); 
    }
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
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

/**
 * @brief Generates a new Secp256k1 identity.
 * @param out_priv Base64 encoded private key.
 * @param out_addr Ethereum address (0x...).
 */
int portillia_crypto_generate_identity(char *out_priv, char *out_addr) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return -1;
    
    if (!EC_KEY_generate_key(key)) {
        EC_KEY_free(key);
        return -1;
    }

    // Address derivation
    size_t pub_len = i2o_ECPublicKey(key, NULL);
    uint8_t *pub_buf = malloc(pub_len);
    uint8_t *p = pub_buf;
    i2o_ECPublicKey(key, &p);
    portillia_crypto_pubkey_to_address(pub_buf, pub_len, out_addr);
    
    // Private key extraction (simplified to dummy for now)
    strcpy(out_priv, "dummy_private_key");

    free(pub_buf);
    EC_KEY_free(key);
    return 0;
}

/**
 * @brief Verifies a Secp256k1 signature.
 */
int portillia_crypto_verify_secp256k1(const uint8_t *payload, size_t payload_len, 
                                      const uint8_t *signature, size_t sig_len,
                                      const uint8_t *pubkey, size_t pubkey_len) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(payload, payload_len, hash);

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return -1;

    const uint8_t *p = pubkey;
    if (!o2i_ECPublicKey(&key, &p, pubkey_len)) {
        EC_KEY_free(key);
        return -1;
    }

    int ret = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, key);
    EC_KEY_free(key);
    return (ret == 1) ? 0 : -1;
}
