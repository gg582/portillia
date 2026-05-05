#ifndef PORTILLIA_PORTAL_KEYLESS_ECH_H
#define PORTILLIA_PORTAL_KEYLESS_ECH_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate ECH keys from a SIWE private key, seed, and public name.
 *
 * Uses HKDF-SHA256 to derive an X25519 key pair, then builds an ECHConfig
 * and writes it (with the PKCS#8 private key) to a PEM file compatible with
 * OpenSSL/BoringSSL ECH server configuration.
 *
 * @param siwe_private_key 64-character hex secp256k1 private key.
 * @param seed             Free-form seed string (trimmed).
 * @param public_name      DNS public name for ECH (max 255 chars).
 * @param out_pem_path     Output PEM file path.
 * @return 0 on success, -1 on error.
 */
int portillia_keyless_ech_generate_keys(const char *siwe_private_key, const char *seed, const char *public_name, const char *out_pem_path);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_PORTAL_KEYLESS_ECH_H */
