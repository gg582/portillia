/**
 * @file discovery.h
 * @brief Relay discovery and gossip protocol management.
 */

#ifndef PORTILLIA_PORTAL_DISCOVERY_H
#define PORTILLIA_PORTAL_DISCOVERY_H

#include <portillia/types/types.h>
#include <portillia/discovery/relay_set.h>
#include <cwist/core/sstring/sstring.h>
#include <pthread.h>

/**
 * @struct discovery_config
 * @brief Configuration for the discovery maintenance loop.
 */
typedef struct {
    char *relay_url; /**< This relay's own public relay URL */
    char *advertise_url; /**< Public relay URL advertised in descriptors */
    char *bootstrap_urls; /**< Comma-separated list of bootstrap URLs */
    portillia_relay_set_t *relay_set; /**< The set to manage (new ttak-based) */
    int wireguard_port; /**< WireGuard listen port for overlay */
    int max_routing; /**< Maximum number of discovery routing attempts per refresh */
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
 * @brief Poll discovery endpoint of a peer relay.
 */
void portillia_discovery_poll(discovery_config *cfg, const char *url);

extern char g_desc_priv_hex[65];
extern char g_desc_addr[43];
void ensure_descriptor_identity(void);

#endif // PORTILLIA_PORTAL_DISCOVERY_H
