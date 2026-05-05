/** @file expose.h
 * @brief SDK for exposing services — C port of portal-tunnel/sdk/expose.go.
 *
 * All heap objects are managed by the global EpochGC.
 */
#ifndef PORTILLIA_SDK_EXPOSE_H
#define PORTILLIA_SDK_EXPOSE_H

#include <portillia/types/types.h>
#include <portillia/mem/gc.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Forward declarations ---------- */

typedef struct portillia_listener portillia_listener_t;
typedef struct portillia_relay_set portillia_relay_set_t;
typedef struct portillia_http_route portillia_http_route_t;

/* ---------- HTTP route ---------- */

typedef struct portillia_http_route {
    char *path;
    char *upstream;
} portillia_http_route_t;

/* ---------- Exposure configuration ---------- */

typedef struct portillia_expose_config {
    char **relay_urls;
    size_t relay_urls_count;
    bool discovery;
    char *identity_path;
    char *identity_json;
    char *name;
    char *target_addr;
    char *udp_addr;
    bool udp_enabled;
    bool tcp_enabled;
    char **multi_hop;
    size_t multi_hop_count;
    int multi_hop_depth;
    bool ban_mitm;
    int max_active_relays;
    portillia_lease_metadata_t metadata;
} portillia_expose_config_t;

/* ---------- Exposure ---------- */

typedef struct portillia_exposure {
    /* Lifecycle */
    atomic_bool cancelled;
    pthread_mutex_t cancel_mu;
    pthread_cond_t cancel_cond;
    bool done;

    /* Configuration */
    portillia_identity_t identity;
    char **explicit_relays;
    size_t explicit_relays_count;
    char **seed_only_relays;
    size_t seed_only_relays_count;
    char *target_addr;
    char *udp_addr;
    bool udp_enabled;
    bool tcp_enabled;
    char **multi_hop;
    size_t multi_hop_count;
    int multi_hop_depth;
    bool ban_mitm;
    int max_active_relays;
    portillia_lease_metadata_t metadata;

    /* Channels / Queues */
    void *accepted;      /* portillia_conn_channel_t * */
    void *datagrams;     /* portillia_datagram_channel_t * */

    /* Relay management */
    struct portillia_relay_set *relay_set;
    pthread_rwlock_t listener_mu;
    char **listener_urls;
    struct portillia_listener **listeners;
    size_t listener_count;
    size_t listener_cap;

    /* Sync */
    pthread_once_t close_once;
    atomic_uint_least64_t conn_seq;

    /* Accept threads (parallel to listeners) */
    pthread_t *listener_accept_tids;

    /* Background threads */
    pthread_t discovery_tid;
    bool discovery_running;
} portillia_exposure_t;

/* ---------- Public API ---------- */

/**
 * @brief Creates relay listeners for the selected relay pool and exposes a
 * dynamic listener hub for accepting traffic from all of them.
 */
portillia_exposure_t *portillia_expose(const portillia_expose_config_t *cfg);

/**
 * @brief Attach an explicit relay to a running exposure.
 */
int portillia_exposure_add_relay(portillia_exposure_t *e, const char *relay_url);

/**
 * @brief Detach a relay from the running exposure.
 */
int portillia_exposure_remove_relay(portillia_exposure_t *e, const char *relay_url);

/**
 * @brief Keep a relay as a discovery seed while removing it from the active pool.
 */
int portillia_exposure_seed_relay(portillia_exposure_t *e, const char *relay_url);

/**
 * @brief Set or clear the explicit multi-hop relay path.
 */
int portillia_exposure_set_multi_hop(portillia_exposure_t *e, char **relay_urls, size_t count);

/**
 * @brief Returns the currently active relay URLs (sorted).
 * Caller must free the returned array (but not its strings) with portillia_gc_free_later.
 */
char **portillia_exposure_active_relay_urls(portillia_exposure_t *e, size_t *out_count);

/**
 * @brief Network address of the exposure.
 */
portillia_net_addr_t portillia_exposure_addr(const portillia_exposure_t *e);

/**
 * @brief Returns a copy of the exposure identity.
 * Caller must call portillia_identity_cleanup on the result.
 */
portillia_identity_t portillia_exposure_identity(const portillia_exposure_t *e);

/**
 * @brief Snapshot of current tunnel status.
 * Caller must call portillia_agent_tunnel_status_cleanup on the result.
 */
portillia_agent_tunnel_status_t portillia_exposure_snapshot(portillia_exposure_t *e);

/**
 * @brief Accept a datagram frame (UDP).
 * @return 0 on success, -1 on error (sets errno).
 */
int portillia_exposure_accept_datagram(portillia_exposure_t *e, portillia_datagram_frame_t *out_frame);

/**
 * @brief Send a datagram frame (UDP).
 * @return 0 on success, -1 on error.
 */
int portillia_exposure_send_datagram(portillia_exposure_t *e, const portillia_datagram_frame_t *frame);

/**
 * @brief Wait until at least one relay is ready for datagrams.
 * @return Array of UDP addresses on success (caller frees with portillia_gc_free_later), NULL on error.
 */
char **portillia_exposure_wait_datagram_ready(portillia_exposure_t *e, int timeout_ms, size_t *out_count);

/**
 * @brief Run HTTP routes through the exposure.
 * @return 0 on success, -1 on error.
 */
int portillia_exposure_run_http_routes(portillia_exposure_t *e,
                                        const portillia_http_route_t *routes,
                                        size_t routes_count,
                                        const char *local_addr);

/**
 * @brief Run an HTTP handler through the exposure.
 * @return 0 on success, -1 on error.
 */
int portillia_exposure_run_http(portillia_exposure_t *e, void *handler, const char *local_addr);

/**
 * @brief Accept a TCP connection from the exposure.
 * @return Connection object on success, NULL on error.
 */
portillia_net_conn_t *portillia_exposure_accept(portillia_exposure_t *e);

/**
 * @brief Close the exposure and all its relay listeners.
 * Idempotent; safe to call multiple times.
 */
void portillia_exposure_close(portillia_exposure_t *e);

/* ---------- Connection helpers ---------- */

/**
 * @brief Close a connection returned by Accept().
 */
void portillia_net_conn_close(portillia_net_conn_t *conn);

/**
 * @brief Read from connection.
 */
ssize_t portillia_net_conn_read(portillia_net_conn_t *conn, void *buf, size_t len);

/**
 * @brief Write to connection.
 */
ssize_t portillia_net_conn_write(portillia_net_conn_t *conn, const void *buf, size_t len);

/**
 * @brief Get local address.
 */
portillia_net_addr_t portillia_net_conn_local_addr(const portillia_net_conn_t *conn);

/**
 * @brief Get remote address.
 */
portillia_net_addr_t portillia_net_conn_remote_addr(const portillia_net_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_SDK_EXPOSE_H */
