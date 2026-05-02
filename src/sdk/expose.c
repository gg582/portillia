/** @file expose.c
 * @brief Implementation of service exposure logic.
 */
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <cwist/core/sstring/sstring.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

typedef struct portillia_exposure {
    portillia_identity *identity;
    cwist_sstring *target_addr;
    bool running;
} portillia_exposure;

/**
 * @brief Exposes a local service via Portillia relay.
 * @param target The local address to expose.
 * @param relay_url The relay server URL.
 * @return Allocated exposure context, or NULL on error.
 */
portillia_exposure *portillia_expose(const char *target, const char *relay_url) {
    LOG_INFO("SDK: Exposing %s through %s", target, relay_url);
    portillia_exposure *e = malloc(sizeof(portillia_exposure));

    e->target_addr = cwist_sstring_create();
    cwist_sstring_assign(e->target_addr, (char *)target);
    e->running = true;
    
    // In a real implementation, this would:
    // 1. Generate/Resolve identity
    // 2. Register with relay server via API
    // 3. Start a backhaul connection (TCP/QUIC)
    // 4. Proxy traffic from backhaul to target_addr
    
    return e;
}

void portillia_exposure_stop(portillia_exposure *e) {
    if (!e) return;
    e->running = false;
    cwist_sstring_destroy(e->target_addr);
    free(e);
}
