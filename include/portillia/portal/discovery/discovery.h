#include <portillia/types/types.h>
#include <cwist/core/sstring/sstring.h>

typedef struct {
    char *relay_url;
    char *bootstrap_urls;
} discovery_config;

void portillia_discovery_announce(discovery_config *cfg, portillia_relay_descriptor *desc);
void *discovery_maintenance_loop(void *arg);
