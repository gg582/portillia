/** @file expose.h
 * @brief SDK for exposing services.
 */
#ifndef PORTILLIA_SDK_H
#define PORTILLIA_SDK_H

#include <portillia/types/types.h>
#include <stdbool.h>

typedef struct portillia_exposure {
    // Mirroring Go Exposure struct
    portillia_identity *identity;
    char **explicit_relays;
    size_t explicit_relays_count;
    char *target_addr;
    char *udp_addr;
    bool udp_enabled;
    bool tcp_enabled;
    char **multi_hop;
    size_t multi_hop_count;
    int multi_hop_depth;
    bool ban_mitm;
    int max_active_relays;
    portillia_lease_metadata metadata;
    
    // Internal state
    bool running;
    void *relay_set; // Pointer to discovery.RelaySet equivalent
    void *relay_listeners; // Map equivalent
} portillia_exposure;

typedef struct {
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
    portillia_lease_metadata metadata;
} portillia_expose_config;

portillia_exposure *portillia_expose(portillia_expose_config cfg);
void portillia_exposure_stop(portillia_exposure *e);

#endif
