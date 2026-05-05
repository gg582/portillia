/** @file listener.h
 * @brief Single relay listener — C port of portal-tunnel/sdk/listener.go.
 */
#ifndef PORTILLIA_SDK_LISTENER_H
#define PORTILLIA_SDK_LISTENER_H

#include <portillia/types/types.h>
#include <portillia/discovery/relay_set.h>
#include <portillia/transport/stream_client.h>
#include <portillia/transport/datagram_client.h>
#include <portillia/sdk/api_client.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct portillia_listener_lease {
    char *hostname;
    char *udp_addr;
    char *tcp_addr;
    char *access_token;
    time_t expires_at;
    int sni_port;
    portillia_hop_route_t *hop_routes;
    size_t hop_routes_count;
    void *tls_ctx; /* SSL_CTX* for inner TLS, or NULL */
} portillia_listener_lease_t;

typedef struct portillia_listener {
    char *relay_url;
    portillia_identity_t identity;
    portillia_lease_metadata_t metadata;
    portillia_relay_set_t *relay_set;
    char **multi_hop;
    size_t multi_hop_count;
    bool udp_enabled;
    bool tcp_enabled;
    int ready_target;
    int retry_count;
    int retry_wait_sec;
    int lease_ttl_sec;
    int renew_before_sec;
    bool insecure_skip_verify;

    /* Transport */
    portillia_stream_client_t *stream;
    portillia_datagram_client_t *datagram;
    portillia_http_client_t *http_client;

    /* Internal */
    bool cancelled;
    bool run_started;
    pthread_mutex_t lease_mu;
    portillia_listener_lease_t *lease;
    pthread_t run_tid;

    /* Error signalling for run_lease wait */
    pthread_mutex_t run_err_mu;
    pthread_cond_t run_err_cond;
    int run_err;
} portillia_listener_t;

/* ---------- Lifecycle ---------- */

portillia_listener_t *portillia_listener_new(const char *relay_url,
                                              const portillia_identity_t *identity,
                                              const portillia_lease_metadata_t *metadata,
                                              portillia_relay_set_t *relay_set,
                                              char **multi_hop, size_t multi_hop_count,
                                              bool udp_enabled, bool tcp_enabled,
                                              int retry_count,
                                              bool insecure_skip_verify);

void portillia_listener_close(portillia_listener_t *l);

/* ---------- I/O ---------- */

/**
 * @brief Accept a TCP connection from the relay.
 * @return Connection handle on success, NULL on error (sets errno).
 */
portillia_net_conn_t *portillia_listener_accept(portillia_listener_t *l);

/**
 * @brief Accept a datagram frame.
 * @return 0 on success, -1 on error.
 */
int portillia_listener_accept_datagram(portillia_listener_t *l, portillia_datagram_frame_t *out, bool *out_cancelled);

/**
 * @brief Send a datagram frame.
 * @return 0 on success, -1 on error.
 */
int portillia_listener_send_datagram(portillia_listener_t *l, const portillia_datagram_frame_t *frame);

/**
 * @brief Get datagram readiness.
 * @return udp_addr (caller must free with portillia_gc_free_later), ready, pending.
 */
char *portillia_listener_datagram_ready(portillia_listener_t *l, bool *out_ready, bool *out_pending);

/* ---------- Lease introspection ---------- */

bool portillia_listener_lease_snapshot(portillia_listener_t *l, portillia_listener_lease_t *out);
char *portillia_listener_public_url(portillia_listener_t *l);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_SDK_LISTENER_H */
