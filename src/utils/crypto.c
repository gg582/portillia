#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdint.h>

// Simplified Secp256k1 compact signing using OpenSSL (NID_secp256k1)
int portillia_crypto_sign_secp256k1(const uint8_t *data, size_t len, const uint8_t *priv_key, uint8_t *out) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_EC, NULL, priv_key, 32);
    if (!pkey) return -1;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    size_t sig_len = 64;
    int res = EVP_DigestSign(mdctx, out, &sig_len, hash, SHA256_DIGEST_LENGTH);
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return res == 1 ? 0 : -1;
}

