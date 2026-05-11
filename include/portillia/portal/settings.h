/**
 * @file settings.h
 * @brief Persistent configuration management for the Portal relay server.
 */

#ifndef PORTILLIA_PORTAL_SETTINGS_H
#define PORTILLIA_PORTAL_SETTINGS_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @struct portillia_settings
 * @brief Represents the global persisted settings of the relay server.
 */
typedef struct {
    char *approval_mode; /**< "auto" or "manual" */
    bool landing_page_enabled; /**< Whether to serve the landing page */
    int64_t default_bps_limit; /**< Global default throughput limit */
    bool udp_enabled; /**< Global UDP tunnel toggle */
    bool tcp_port_enabled; /**< Global raw TCP port toggle */
    char *encrypted_client_hello_seed; /**< Seed for ECH key derivation */

    // Policy Engine
    char **banned_identities; /**< List of banned Ethereum addresses */
    int banned_count; /**< Number of banned identities */
    int banned_capacity; /**< Allocated capacity of banned_identities */
    char **approved_identities; /**< List of manually approved addresses */
    int approved_count; /**< Number of approved identities */
    int approved_capacity; /**< Allocated capacity of approved_identities */
    char **trusted_proxy_cidrs; /**< CIDR ranges for trusted proxies */
    int trusted_proxy_count; /**< Number of trusted proxy CIDRs */
    int trusted_proxy_capacity; /**< Allocated capacity of trusted_proxy_cidrs */
    bool trust_proxy_headers; /**< Whether to trust X-Forwarded-For etc. */
    char *path; /**< The file path where these settings are stored */
} portillia_settings;

/**
 * @brief Loads settings from a JSON file.
 * @param path Path to the settings.json file.
 * @return Allocated settings structure.
 */
portillia_settings* portillia_settings_load(const char *path);

/**
 * @brief Saves settings to a JSON file.
 * @param path Destination file path.
 * @param s Settings to save.
 */
void portillia_settings_save(const char *path, portillia_settings *s);

/**
 * @brief Frees a settings structure.
 * @param s Pointer to settings instance.
 */
void portillia_settings_free(portillia_settings *s);

/**
 * @brief Adds an identity to the ban list.
 */
void portillia_settings_ban_identity(portillia_settings *s, const char *addr);

/**
 * @brief Removes an identity from the ban list.
 */
void portillia_settings_unban_identity(portillia_settings *s, const char *addr);

/**
 * @brief Manually approves an identity.
 */
void portillia_settings_approve_identity(portillia_settings *s, const char *addr);

#endif // PORTILLIA_PORTAL_SETTINGS_H