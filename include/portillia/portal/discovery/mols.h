#ifndef PORTILLIA_PORTAL_DISCOVERY_MOLS_H
#define PORTILLIA_PORTAL_DISCOVERY_MOLS_H

#include <portillia/discovery/relay_set.h>
#include <stddef.h>

#define MOLS_ORDER              64
#define MOLS_CANDIDATE_DEPTH    8
#define MOLS_MIN_ACTIVE_NODES   2
#define MOLS_DEFAULT_MAX_ACTIVE_RELAYS 3

char **mols_select_priority(portillia_relay_state_t **states, int count,
                            const char *local_address,
                            int require_udp, int require_tcp,
                            int max_active_relays,
                            size_t *out_count);

char **mols_select_multihop(portillia_relay_state_t **states, int count,
                            const char *local_address,
                            int require_udp, int require_tcp,
                            int multi_hop_depth,
                            size_t *out_count);

#endif
