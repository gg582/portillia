#ifndef PORTILLIA_CRYPTO_H
#define PORTILLIA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct portillia_identity portillia_identity;

portillia_identity *portillia_identity_create();
void portillia_identity_destroy(portillia_identity *identity);

int portillia_crypto_generate_identity(char *out_priv, char *out_addr);
int portillia_crypto_sign_data(const uint8_t *priv_key, const uint8_t *msg, size_t msg_len, uint8_t *sig_out);
int portillia_crypto_verify_signature(const uint8_t *pub_key, const uint8_t *msg, size_t msg_len, const uint8_t *sig);
int portillia_crypto_recover_secp256k1_compact(const uint8_t *msg_hash, const uint8_t *sig_compact, int recid, uint8_t *pubkey_out);

#endif // PORTILLIA_CRYPTO_H
