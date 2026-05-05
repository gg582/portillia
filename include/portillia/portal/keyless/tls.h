/** @file tls.h
 * @brief Keyless TLS helpers for portillia.
 */
#ifndef PORTILLIA_PORTAL_KEYLESS_TLS_H
#define PORTILLIA_PORTAL_KEYLESS_TLS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Build a server-side TLS context for the leased hostname.
 * @return SSL_CTX* on success, NULL on error.
 */
void *portillia_keyless_build_tls_ctx(const char *keyless_url,
                                      const char *hostname,
                                      bool insecure_skip_verify);

void portillia_tls_setup(void);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_PORTAL_KEYLESS_TLS_H */
