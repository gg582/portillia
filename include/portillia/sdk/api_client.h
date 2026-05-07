/** @file api_client.h
 * @brief SDK HTTP API client — C port of portal-tunnel/sdk/api_client.go.
 */
#ifndef PORTILLIA_SDK_API_CLIENT_H
#define PORTILLIA_SDK_API_CLIENT_H

#include <portillia/types/types.h>
#include <portillia/discovery/relay_set.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- HTTP transport context ---------- */

typedef enum {
    PORTILLIA_HTTP_CONTEXT_DEFAULT = 0,
    PORTILLIA_HTTP_CONTEXT_RELAY,
    PORTILLIA_HTTP_CONTEXT_DISCOVERY,
    PORTILLIA_HTTP_CONTEXT_KEYLESS
} portillia_http_context_t;

typedef struct portillia_http_client portillia_http_client_t;

/**
 * @brief Create an HTTP+TLS client for a relay URL.
 * @param insecure_skip_verify When true, disable TLS peer and hostname verification.
 * @return Client context on success, NULL on error.
 */
portillia_http_client_t *portillia_http_client_create(const char *relay_url,
                                                      bool insecure_skip_verify);

/**
 * @brief Create an HTTP+TLS client for a specific security context.
 *        Each context gets an isolated CURL handle to avoid cross-context leaks.
 */
portillia_http_client_t *portillia_http_client_create_for_context(const char *relay_url,
                                                                   bool insecure_skip_verify,
                                                                   portillia_http_context_t context);
void portillia_http_client_destroy(portillia_http_client_t *client);
void portillia_http_client_close_idle(portillia_http_client_t *client);

/** @brief Must-style helper: aborts if client creation fails. */
#define MUST_HTTP_CLIENT(url, skip) \
    ({ portillia_http_client_t *_c = portillia_http_client_create((url), (skip)); \
       if (!_c) { LOG_FATAL("Failed to create HTTP client for %s", (url)); abort(); } \
       _c; })

/**
 * @brief Check relay domain compatibility.
 * @return 0 on success, -1 on error.
 */
int portillia_http_client_check_domain(portillia_http_client_t *client);

/* ---------- Lease API ---------- */

/**
 * @brief Register a new lease.
 * @param out_resp  Filled with register response (caller must cleanup).
 * @param out_hops  Filled with hop routes array (caller must free strings + array).
 * @param out_hop_count  Number of hop routes.
 * @return 0 on success, -1 on error.
 */
int portillia_api_register_lease(portillia_http_client_t *client,
                                  const portillia_identity_t *identity,
                                  const portillia_lease_metadata_t *metadata,
                                  portillia_relay_set_t *relay_set,
                                  const char **multi_hop, size_t multi_hop_count,
                                  int ttl_sec, bool udp_enabled, bool tcp_enabled,
                                  portillia_register_response_t *out_resp,
                                  portillia_hop_route_t **out_hops, size_t *out_hop_count);

/**
 * @brief Renew an existing lease.
 * @return 0 on success, -1 on error.
 */
int portillia_api_renew_lease(portillia_http_client_t *client,
                               int ttl_sec,
                               const char *access_token,
                               const char *reported_ip,
                               const portillia_identity_t *identity,
                               portillia_relay_set_t *relay_set,
                               portillia_hop_route_t *hops, size_t hop_count,
                               portillia_renew_response_t *out_resp);

/**
 * @brief Unregister a lease.
 * @return 0 on success, -1 on error.
 */
int portillia_api_unregister_lease(portillia_http_client_t *client,
                                    const char *access_token,
                                    portillia_hop_route_t *hops, size_t hop_count);

/* ---------- Hop route sync ---------- */

/**
 * @brief Sync (register or delete) hop routes for multi-hop.
 * @param method "POST" to register, "DELETE" to unregister.
 * @return 0 on success, -1 on error.
 */
int portillia_api_sync_hop_routes(portillia_http_client_t *client,
                                   const char *method,
                                   time_t expires_at,
                                   const portillia_identity_t *identity,
                                   portillia_relay_set_t *relay_set,
                                   portillia_hop_route_t *hops, size_t hop_count);

/* ---------- Discovery API ---------- */

/**
 * @brief Fetch relay descriptors from a relay's discovery endpoint.
 * @return 0 on success, -1 on error.
 */
int portillia_api_discover_relays(portillia_http_client_t *client, portillia_discovery_response_t *out_resp);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_SDK_API_CLIENT_H */
