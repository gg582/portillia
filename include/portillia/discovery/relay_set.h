/** @file relay_set.h
 * @brief Relay discovery set — C port of portal-tunnel/portal/discovery/relayset.go.
 */
#ifndef PORTILLIA_DISCOVERY_RELAY_SET_H
#define PORTILLIA_DISCOVERY_RELAY_SET_H

#include <portillia/types/types.h>
#include <portillia/mem/gc.h>
#include <ttak/ht/table.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PORTILLIA_DISCOVERY_DESCRIPTOR_TTL_SEC       (5 * 60)
#define PORTILLIA_DEFAULT_DIRECT_RECOVERY_BACKOFF_SEC 60
#define PORTILLIA_MAX_DIRECT_RECOVERY_BACKOFF_SEC     (5 * 60)
#define PORTILLIA_MAX_ANNOUNCED_RELAYS                1024
#define PORTILLIA_ANNOUNCE_CLOCK_SKEW_TOLERANCE_SEC   (5 * 60)
#define PORTILLIA_ANNOUNCE_MAX_VALIDITY_SEC           (24 * 60 * 60)
#define PORTILLIA_DISCOVERY_POLL_INTERVAL_SEC         30

/* ---------- RelayState ---------- */

typedef struct portillia_relay_state {
    portillia_relay_descriptor_t descriptor;
    bool bootstrap;
    bool confirmed;
    bool banned;
    time_t last_seen_at;

    double discovery_rtt_ms;   /* 0 if unset */
    time_t discovery_rtt_at;

    int discovery_failures;
    int active_failures;
    time_t next_discovery_refresh_at;
    time_t suppress_active_until;

    bool is_saturated;
    uint32_t load_factor_fixed;
    time_t load_factor_at;
} portillia_relay_state_t;

/* ---------- ClientState ---------- */

typedef struct portillia_client_state {
    char **explicit_relay_urls;
    size_t explicit_relay_urls_count;
    char **suppressed_relay_urls;
    size_t suppressed_relay_urls_count;
    int max_active_relays;
    int multi_hop_depth;
    bool require_udp;
    bool require_tcp;
    char *local_address;
} portillia_client_state_t;

/* ---------- Key index entry (rollback defense) ---------- */

typedef struct portillia_key_index_entry {
    time_t issued_at;
    time_t tombstone_until;
} portillia_key_index_entry_t;

/* ---------- RelaySet ---------- */

typedef struct portillia_relay_set {
    pthread_rwlock_t mu;
    void *relays;      /* ttak_table_t*  URL -> portillia_relay_state_t* */
    void *key_index;   /* ttak_table_t*  address -> portillia_key_index_entry_t* */
} portillia_relay_set_t;

/* ---------- Lifecycle ---------- */

portillia_relay_set_t *portillia_relay_set_create(const char **bootstrap_urls, size_t count);
void portillia_relay_set_free(portillia_relay_set_t *set);

/* ---------- Bootstrap management ---------- */

void portillia_relay_set_set_bootstrap_urls(portillia_relay_set_t *set, const char **urls, size_t count);
void portillia_relay_set_add_bootstrap_url(portillia_relay_set_t *set, const char *url);
void portillia_relay_set_remove_bootstrap_url(portillia_relay_set_t *set, const char *url);

/* ---------- Query ---------- */

size_t portillia_relay_set_all_relays(portillia_relay_set_t *set, portillia_relay_state_t **out_states);
size_t portillia_relay_set_confirmed_relays(portillia_relay_set_t *set, portillia_relay_state_t **out_states);

/**
 * @brief Select priority relays for the given client state.
 * Caller must free the returned array (but not strings) with portillia_gc_free_later.
 */
char **portillia_relay_set_priority_relays(portillia_relay_set_t *set, const portillia_client_state_t *client, size_t *out_count);

/**
 * @brief Select an automatic multi-hop route.
 * Caller must free the returned array (but not strings) with portillia_gc_free_later.
 */
char **portillia_relay_set_priority_multi_hop(portillia_relay_set_t *set, const portillia_client_state_t *client, size_t *out_count);

size_t portillia_relay_set_overlay_peers(portillia_relay_set_t *set, portillia_relay_state_t **out_states);
bool portillia_relay_set_overlay_descriptor(portillia_relay_set_t *set, const char *relay_url, time_t now, portillia_relay_descriptor_t *out_desc);

size_t portillia_relay_set_bootstrap_urls(portillia_relay_set_t *set, char ***out_urls);
size_t portillia_relay_set_descriptors(portillia_relay_set_t *set, const portillia_relay_descriptor_t *self, portillia_relay_descriptor_t **out_descs);

/* ---------- Mutation ---------- */

void portillia_relay_set_ban_url(portillia_relay_set_t *set, const char *url);
void portillia_relay_set_allow_url(portillia_relay_set_t *set, const char *url);
void portillia_relay_set_confirm_url(portillia_relay_set_t *set, const char *url);
void portillia_relay_set_unconfirm_url(portillia_relay_set_t *set, const char *url);

/**
 * @brief Apply a discovery response from a target relay.
 * @return 0 on success, -1 on error (errno set).
 */
int portillia_relay_set_apply_discovery_response(portillia_relay_set_t *set, const char *target_url,
                                                  const portillia_discovery_response_t *resp, time_t now,
                                                  bool *out_changed);

/**
 * @brief Insert a single announced descriptor.
 * @return 0 on success, -1 on error (errno set).
 */
int portillia_relay_set_insert_announced(portillia_relay_set_t *set, const portillia_relay_descriptor_t *desc, time_t now);

void portillia_relay_set_record_discovery_rtt(portillia_relay_set_t *set, const char *url, double rtt_ms, time_t measured_at);

/**
 * @brief Record a discovery failure.
 * @return backed_off, backoff_reason (caller must free), failure_count.
 */
bool portillia_relay_set_record_discovery_failure(portillia_relay_set_t *set, const char *url, int recovery_failures, char **out_reason, int *out_count);

bool portillia_relay_set_record_active_failure(portillia_relay_set_t *set, const char *url, int recovery_failures, char **out_reason, int *out_count);

/* ---------- Utility ---------- */

bool portillia_relay_state_has_observed_descriptor(const portillia_relay_state_t *state);
bool portillia_relay_descriptor_has_overlay_peer(const portillia_relay_descriptor_t *desc);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_DISCOVERY_RELAY_SET_H */
