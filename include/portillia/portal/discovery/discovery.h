/**
 * @file discovery.h
 * @brief Relay discovery and gossip protocol management.
 */

#ifndef PORTILLIA_PORTAL_DISCOVERY_H
#define PORTILLIA_PORTAL_DISCOVERY_H

#include <portillia/types/types.h>
#include <cwist/core/sstring/sstring.h>
#include <pthread.h>

/**
 * @brief Maximum number of relays to track in the local discovery set.
 */
#define MAX_RELAYS 256

/**
 * @struct portillia_relay_state
 * @brief Local tracking state for a discovered relay.
 */
typedef struct {
    portillia_relay_descriptor descriptor; /**< The cryptographically signed descriptor */
    bool bootstrap; /**< Whether this is a hardcoded bootstrap relay */
    bool banned; /**< Whether this relay is locally banned */
    int discovery_failures; /**< Count of consecutive poll failures */
    time_t next_discovery_refresh_at; /**< Next scheduled poll time */
} portillia_relay_state;

/**
 * @struct portillia_relay_set
 * @brief Thread-safe collection of all known relays.
 */
typedef struct {
    portillia_relay_state relays[MAX_RELAYS]; /**< Array of relay states */
    int count; /**< Current number of tracked relays */
    pthread_mutex_t mu; /**< Mutex for concurrent access */
} portillia_relay_set;

/**
 * @struct discovery_config
 * @brief Configuration for the discovery maintenance loop.
 */
typedef struct {
    char *relay_url; /**< This relay's own API URL */
    char *bootstrap_urls; /**< Comma-separated list of bootstrap URLs */
    portillia_relay_set *relay_set; /**< The set to manage */
} discovery_config;

/**
 * @brief Announces this relay's state to peers.
 */
void portillia_discovery_announce(discovery_config *cfg, portillia_relay_descriptor *desc);

/**
 * @brief Main loop for discovery maintenance (polling and announcing).
 */
void *discovery_maintenance_loop(void *arg);
void portillia_discovery_publish_self(discovery_config *cfg);

/**
 * @brief Creates a new relay set.
 */
portillia_relay_set* portillia_relay_set_new();

/**
 * @brief Frees a relay set and all its descriptors.
 */
void portillia_discovery_relay_set_free(portillia_relay_set *set);

/**
 * @brief Updates or inserts a relay descriptor into the set.
 */
void portillia_relay_set_upsert(portillia_relay_set *set, portillia_relay_descriptor desc);

extern char g_desc_priv_hex[65];
extern char g_desc_addr[43];
void ensure_descriptor_identity(void);

#endif // PORTILLIA_PORTAL_DISCOVERY_H
