#ifndef PORTILLIA_PORTAL_IDENTITY_H
#define PORTILLIA_PORTAL_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char *name;
    char *address;
    char *public_key;
    char *private_key;
    char *token_secret;
    char *wireguard_public_key;
    char *wireguard_private_key;
    char *encrypted_client_hello_seed;
} portillia_relay_identity;

/**
 * @brief Load relay identity from <identity_path>/identity.json.
 *
 * If the file does not exist or is missing required fields, a new identity is
 * generated via the Rust bridge (secp256k1 + WireGuard keys + token secret +
 * ECH seed), persisted to disk, and returned.
 *
 * @param identity_path Directory containing identity.json.
 * @param name Default name for a newly created identity (usually root hostname).
 * @return Loaded/created identity, or NULL on failure. Caller must free with
 *         portillia_relay_identity_free().
 */
portillia_relay_identity *portillia_relay_identity_load_or_create(const char *identity_path, const char *name);

void portillia_relay_identity_free(portillia_relay_identity *identity);

/**
 * @brief Check whether all required relay identity fields are present.
 */
bool portillia_relay_identity_is_complete(const portillia_relay_identity *identity);

#endif // PORTILLIA_PORTAL_IDENTITY_H
