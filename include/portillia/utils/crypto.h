#ifndef PORTILLIA_CRYPTO_H
#define PORTILLIA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct portillia_identity portillia_identity;

portillia_identity *portillia_identity_create();
void portillia_identity_destroy(portillia_identity *identity);

int portillia_crypto_generate_identity(char *out_priv, char *out_addr);
int portillia_crypto_derive_address_from_private_key(const char *private_key_hex, char *out_addr, size_t out_addr_len);
int portillia_crypto_sign_siwe_message(const char *siwe_message, const char *private_key_hex, char *out_sig, size_t out_len);
bool portillia_crypto_verify_siwe_signature_address(const char *siwe_message, const char *siwe_signature, const char *expected_address);
void portillia_crypto_keccak256(const uint8_t *data, size_t len, uint8_t *out);
void portillia_crypto_pubkey_to_address(const uint8_t *pubkey, size_t pubkey_len, char *out_addr);
int portillia_crypto_derive_overlay_ipv4(const char *pubkey_b64, char *out_ipv4);
int portillia_crypto_sign_data(const uint8_t *priv_key, const uint8_t *msg, size_t msg_len, uint8_t *sig_out);
int portillia_crypto_verify_signature(const uint8_t *pub_key, const uint8_t *msg, size_t msg_len, const uint8_t *sig);
int portillia_crypto_recover_secp256k1_compact(const uint8_t *msg_hash, const uint8_t *sig_compact, int recid, uint8_t *pubkey_out);

#endif // PORTILLIA_CRYPTO_H
