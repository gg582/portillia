#include <portillia/discovery/relay_set.h>
#include <portillia/portal/discovery/mols.h>
#include <portillia/utils/log.h>
#include <ttak/ht/hash.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>

/* ---------- Helpers ---------- */

static void free_relay_state(void *val) {
    portillia_relay_state_t *state = (portillia_relay_state_t *)val;
    if (!state) return;
    portillia_relay_descriptor_cleanup(&state->descriptor);
    free(state);
}

static void free_key_index_entry(void *val) {
    free(val);
}

static int strcasecmp_ptr(const void *a, const void *b) {
    return strcasecmp((const char *)a, (const char *)b);
}

static char *str_tolower_dup(const char *s) {
    if (!s) return NULL;
    char *out = strdup(s);
    if (!out) return NULL;
    for (char *p = out; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') *p += ('a' - 'A');
    }
    return out;
}

/* ---------- Table iteration helpers ---------- */

static int relay_set_collect_states(ttak_table_t *table, portillia_relay_state_t **out, int max) {
    int n = 0;
    for (size_t i = 0; i < table->capacity && n < max; i++) {
        if (table->ctrls[i] == OCCUPIED) {
            out[n++] = (portillia_relay_state_t *)table->values[i];
        }
    }
    return n;
}

/* ---------- Lifecycle ---------- */

portillia_relay_set_t *portillia_relay_set_create(const char **bootstrap_urls, size_t count) {
    portillia_relay_set_t *set = calloc(1, sizeof(*set));
    if (!set) return NULL;
    pthread_rwlock_init(&set->mu, NULL);

    ttak_table_t *relays = calloc(1, sizeof(ttak_table_t));
    ttak_table_t *key_index = calloc(1, sizeof(ttak_table_t));
    if (!relays || !key_index) {
        free(relays);
        free(key_index);
        free(set);
        return NULL;
    }

    ttak_table_init(relays, 64, NULL, strcasecmp_ptr, free, free_relay_state);
    ttak_table_init(key_index, 64, NULL, strcasecmp_ptr, free, free_key_index_entry);

    set->relays = relays;
    set->key_index = key_index;

    if (bootstrap_urls && count > 0) {
        portillia_relay_set_set_bootstrap_urls(set, bootstrap_urls, count);
    }
    return set;
}

void portillia_relay_set_free(portillia_relay_set_t *set) {
    if (!set) return;
    ttak_table_destroy((ttak_table_t *)set->relays, 0);
    free(set->relays);
    ttak_table_destroy((ttak_table_t *)set->key_index, 0);
    free(set->key_index);
    pthread_rwlock_destroy(&set->mu);
    free(set);
}

/* ---------- Bootstrap management ---------- */

void portillia_relay_set_set_bootstrap_urls(portillia_relay_set_t *set, const char **urls, size_t count) {
    if (!set) return;
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;

    /* Unmark all existing bootstrap */
    for (size_t i = 0; i < relays->capacity; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            state->bootstrap = false;
        }
    }

    /* Add/mark bootstrap URLs */
    for (size_t j = 0; j < count; j++) {
        const char *url = urls[j];
        if (!url || !url[0]) continue;
        portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
        if (state) {
            state->bootstrap = true;
        } else {
            state = calloc(1, sizeof(*state));
            if (!state) continue;
            state->bootstrap = true;
            state->descriptor.api_https_addr = strdup(url);
            ttak_table_put(relays, strdup(url), strlen(url), state, 0);
        }
    }

    /* Evict disposable non-bootstrap entries */
    for (size_t i = 0; i < relays->capacity; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            if (!state->bootstrap && !state->confirmed && !state->banned &&
                state->discovery_failures == 0 && state->active_failures == 0 &&
                state->next_discovery_refresh_at == 0 && state->suppress_active_until == 0 &&
                !state->descriptor.address) {
                char *key = (char *)relays->keys[i];
                ttak_table_remove(relays, key, strlen(key), 0);
            }
        }
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_add_bootstrap_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url || !url[0]) return;
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (state) {
        state->bootstrap = true;
    } else {
        state = calloc(1, sizeof(*state));
        if (state) {
            state->bootstrap = true;
            state->descriptor.api_https_addr = strdup(url);
            ttak_table_put(relays, strdup(url), strlen(url), state, 0);
        }
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_remove_bootstrap_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url || !url[0]) return;
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (state) {
        state->bootstrap = false;
        if (!state->confirmed && !state->banned &&
            state->discovery_failures == 0 && state->active_failures == 0 &&
            state->next_discovery_refresh_at == 0 && state->suppress_active_until == 0 &&
            !state->descriptor.address) {
            ttak_table_remove(relays, url, strlen(url), 0);
        }
    }
    pthread_rwlock_unlock(&set->mu);
}

/* ---------- Query ---------- */

size_t portillia_relay_set_all_relays(portillia_relay_set_t *set, portillia_relay_state_t **out_states) {
    if (!set || !out_states) return 0;
    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    size_t n = 0;
    for (size_t i = 0; i < relays->capacity; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            out_states[n++] = (portillia_relay_state_t *)relays->values[i];
        }
    }
    pthread_rwlock_unlock(&set->mu);
    return n;
}

size_t portillia_relay_set_confirmed_relays(portillia_relay_set_t *set, portillia_relay_state_t **out_states) {
    if (!set || !out_states) return 0;
    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    size_t n = 0;
    for (size_t i = 0; i < relays->capacity; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            if (state->confirmed) out_states[n++] = state;
        }
    }
    pthread_rwlock_unlock(&set->mu);
    return n;
}

char **portillia_relay_set_priority_relays(portillia_relay_set_t *set, const portillia_client_state_t *client, size_t *out_count) {
    *out_count = 0;
    if (!set || !client) return NULL;
    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *states[256];
    int n = 0;
    for (size_t i = 0; i < relays->capacity && n < 256; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            if (state->banned) continue;
            states[n++] = state;
        }
    }
    pthread_rwlock_unlock(&set->mu);

    char **result = mols_select_priority(states, n,
                                         client->local_address ? client->local_address : "",
                                         client->require_udp, client->require_tcp,
                                         client->max_active_relays, out_count);
    return result;
}

char **portillia_relay_set_priority_multi_hop(portillia_relay_set_t *set, const portillia_client_state_t *client, size_t *out_count) {
    *out_count = 0;
    if (!set || !client) return NULL;
    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *states[256];
    int n = 0;
    for (size_t i = 0; i < relays->capacity && n < 256; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            if (state->banned) continue;
            states[n++] = state;
        }
    }
    pthread_rwlock_unlock(&set->mu);

    char **result = mols_select_multihop(states, n,
                                         client->local_address ? client->local_address : "",
                                         client->require_udp, client->require_tcp,
                                         client->multi_hop_depth, out_count);
    return result;
}

size_t portillia_relay_set_overlay_peers(portillia_relay_set_t *set, portillia_relay_state_t **out_states) {
    if (!set || !out_states) return 0;
    time_t now = time(NULL);
    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    size_t n = 0;
    for (size_t i = 0; i < relays->capacity; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            if (state->banned) continue;
            if (!state->descriptor.address || !state->descriptor.address[0]) continue;
            if (state->descriptor.expires_at <= now) continue;
            if (!state->descriptor.supports_overlay) continue;
            const char *wg = state->descriptor.wireguard_public_key ? state->descriptor.wireguard_public_key : "";
            if (!wg[0]) continue;
            if (state->descriptor.wireguard_port <= 0 || state->descriptor.wireguard_port > 65535) continue;
            out_states[n++] = state;
        }
    }
    pthread_rwlock_unlock(&set->mu);
    return n;
}

bool portillia_relay_set_overlay_descriptor(portillia_relay_set_t *set, const char *relay_url, time_t now, portillia_relay_descriptor_t *out_desc) {
    if (!set || !relay_url || !out_desc) return false;
    if (now == 0) now = time(NULL);
    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, relay_url, strlen(relay_url), 0);
    pthread_rwlock_unlock(&set->mu);
    if (!state || state->banned || !state->descriptor.address || !state->descriptor.address[0]) return false;
    if (state->descriptor.expires_at <= now) return false;
    if (!state->descriptor.supports_overlay) return false;
    const char *wg = state->descriptor.wireguard_public_key ? state->descriptor.wireguard_public_key : "";
    if (!wg[0]) return false;
    if (state->descriptor.wireguard_port <= 0 || state->descriptor.wireguard_port > 65535) return false;
    *out_desc = state->descriptor;
    return true;
}

size_t portillia_relay_set_bootstrap_urls(portillia_relay_set_t *set, char ***out_urls) {
    if (!set || !out_urls) return 0;
    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    size_t n = 0;
    for (size_t i = 0; i < relays->capacity; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            if (state->bootstrap && !state->banned) n++;
        }
    }
    if (n == 0) { pthread_rwlock_unlock(&set->mu); return 0; }
    char **urls = malloc(sizeof(char *) * n);
    if (!urls) { pthread_rwlock_unlock(&set->mu); return 0; }
    size_t pos = 0;
    for (size_t i = 0; i < relays->capacity; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            if (state->bootstrap && !state->banned) {
                urls[pos++] = strdup(state->descriptor.api_https_addr ? state->descriptor.api_https_addr : "");
            }
        }
    }
    pthread_rwlock_unlock(&set->mu);
    *out_urls = urls;
    return pos;
}

size_t portillia_relay_set_descriptors(portillia_relay_set_t *set, const portillia_relay_descriptor_t *self, portillia_relay_descriptor_t **out_descs) {
    if (!set || !out_descs) return 0;
    time_t now = time(NULL);
    size_t cap = 16;
    size_t n = 0;
    portillia_relay_descriptor_t *out = malloc(sizeof(*out) * cap);
    if (!out) return 0;

    if (self && self->api_https_addr && self->api_https_addr[0] && self->expires_at > now) {
        if (self->api_https_addr && self->api_https_addr[0] && self->expires_at > now) {
            int skip = 0;
            for (size_t j = 0; j < n; j++) {
                if (strcmp(out[j].api_https_addr, self->api_https_addr) == 0) { skip = 1; break; }
            }
            if (!skip) {
                if (n >= cap) { cap *= 2; out = realloc(out, sizeof(*out) * cap); if (!out) { pthread_rwlock_unlock(&set->mu); return 0; } }
                portillia_relay_descriptor_copy(&out[n], self);
                n++;
            }
        }
    }

    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    for (size_t i = 0; i < relays->capacity; i++) {
        if (relays->ctrls[i] == OCCUPIED) {
            portillia_relay_state_t *state = (portillia_relay_state_t *)relays->values[i];
            const portillia_relay_descriptor_t *d = &state->descriptor;
            if (state->banned || !d->address || !d->address[0]) continue;
            if (!d->api_https_addr || !d->api_https_addr[0]) continue;
            if (d->expires_at <= now) continue;
            int skip = 0;
            for (size_t j = 0; j < n; j++) {
                if (strcmp(out[j].api_https_addr, d->api_https_addr) == 0) { skip = 1; break; }
            }
            if (!skip) {
                if (n >= cap) { cap *= 2; out = realloc(out, sizeof(*out) * cap); if (!out) { pthread_rwlock_unlock(&set->mu); return 0; } }
                portillia_relay_descriptor_copy(&out[n], d);
                n++;
            }
        }
    }
    pthread_rwlock_unlock(&set->mu);

    if (n == 0) { free(out); return 0; }
    *out_descs = out;
    return n;
}

/* ---------- Mutation ---------- */

void portillia_relay_set_ban_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (state) {
        state->banned = true;
    } else {
        state = calloc(1, sizeof(*state));
        if (state) {
            state->banned = true;
            state->descriptor.api_https_addr = strdup(url);
            ttak_table_put(relays, strdup(url), strlen(url), state, 0);
        }
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_allow_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (state) state->banned = false;
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_confirm_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (state) {
        state->confirmed = true;
        state->active_failures = 0;
        state->suppress_active_until = 0;
    } else {
        state = calloc(1, sizeof(*state));
        if (state) {
            state->confirmed = true;
            state->descriptor.api_https_addr = strdup(url);
            ttak_table_put(relays, strdup(url), strlen(url), state, 0);
        }
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_unconfirm_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (state) {
        state->confirmed = false;
    }
    pthread_rwlock_unlock(&set->mu);
}

/* ---------- Discovery response application ---------- */

static int validate_descriptor_freshness(const portillia_relay_descriptor_t *desc, time_t now) {
    if (desc->issued_at == 0) { errno = EINVAL; return -1; }
    if (desc->expires_at <= now) { errno = EINVAL; return -1; }
    if (difftime(desc->issued_at, now) > PORTILLIA_ANNOUNCE_CLOCK_SKEW_TOLERANCE_SEC) { errno = EINVAL; return -1; }
    if (difftime(desc->expires_at, desc->issued_at) > PORTILLIA_ANNOUNCE_MAX_VALIDITY_SEC) { errno = EINVAL; return -1; }
    return 0;
}

int portillia_relay_set_apply_discovery_response(portillia_relay_set_t *set, const char *target_url,
                                                  const portillia_discovery_response_t *resp, time_t now,
                                                  bool *out_changed) {
    if (!set || !resp) { errno = EINVAL; return -1; }
    if (now == 0) now = time(NULL);
    if (out_changed) *out_changed = false;

    int protocol_mismatch = (strcmp(resp->protocol_version, PORTILLIA_DISCOVERY_VERSION) != 0);
    int authoritative = (target_url && target_url[0]);

    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    ttak_table_t *kidx = (ttak_table_t *)set->key_index;

    /* Apply each relay descriptor from response */
    for (size_t r = 0; r < resp->relays_count; r++) {
        const portillia_relay_descriptor_t *desc = &resp->relays[r];
        if (!desc->api_https_addr || !desc->api_https_addr[0]) continue;

        if (validate_descriptor_freshness(desc, now) != 0) continue;

        portillia_relay_state_t *existing = ttak_table_get(relays, desc->api_https_addr, strlen(desc->api_https_addr), 0);
        portillia_relay_state_t merged = {0};
        if (existing) {
            merged.bootstrap = existing->bootstrap;
            merged.confirmed = existing->confirmed;
            merged.banned = existing->banned;
            merged.discovery_failures = existing->discovery_failures;
            merged.active_failures = existing->active_failures;
            merged.next_discovery_refresh_at = existing->next_discovery_refresh_at;
            merged.suppress_active_until = existing->suppress_active_until;
            merged.last_seen_at = existing->last_seen_at;
            merged.discovery_rtt_ms = existing->discovery_rtt_ms;
            merged.discovery_rtt_at = existing->discovery_rtt_at;
            merged.is_saturated = existing->is_saturated;
            merged.load_factor_fixed = existing->load_factor_fixed;
            merged.load_factor_at = existing->load_factor_at;
        }
        portillia_relay_descriptor_copy(&merged.descriptor, desc);
        merged.last_seen_at = now;

        int is_authoritative_target = !protocol_mismatch && authoritative && target_url && strcmp(desc->api_https_addr, target_url) == 0;
        if (is_authoritative_target) {
            merged.discovery_failures = 0;
            merged.next_discovery_refresh_at = 0;
        }

        /* Rollback defense via key_index */
        char *addr_lower = str_tolower_dup(desc->address ? desc->address : "");
        if (addr_lower && addr_lower[0]) {
            portillia_key_index_entry_t *prev = ttak_table_get(kidx, addr_lower, strlen(addr_lower), 0);
            if (prev) {
                if (now > prev->tombstone_until && prev->tombstone_until != 0) {
                    /* Tombstone expired, safe to replace */
                } else if (difftime(prev->issued_at, desc->issued_at) > 0) {
                    /* Rollback: older descriptor rejected */
                    free(addr_lower);
                    continue;
                }
            }
        }
        free(addr_lower);

        /* Store merged state */
        portillia_relay_state_t *stored = malloc(sizeof(*stored));
        if (!stored) continue;
        *stored = merged;
        /* Deep copy descriptor because ttak_table may free the old value */
        portillia_relay_descriptor_t tmp = stored->descriptor;
        memset(&stored->descriptor, 0, sizeof(stored->descriptor));
        portillia_relay_descriptor_copy(&stored->descriptor, &tmp);
        portillia_relay_descriptor_cleanup(&tmp);

        ttak_table_put(relays, strdup(desc->api_https_addr), strlen(desc->api_https_addr), stored, 0);

        /* Update key_index */
        if (desc->address && desc->address[0]) {
            char *al = str_tolower_dup(desc->address);
            portillia_key_index_entry_t *entry = malloc(sizeof(*entry));
            if (entry) {
                entry->issued_at = desc->issued_at;
                entry->tombstone_until = desc->issued_at + PORTILLIA_ANNOUNCE_MAX_VALIDITY_SEC;
                ttak_table_put(kidx, al, strlen(al), entry, 0);
            } else {
                free(al);
            }
        }

        if (out_changed) *out_changed = true;
    }

    pthread_rwlock_unlock(&set->mu);

    if (authoritative && protocol_mismatch) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int portillia_relay_set_insert_announced(portillia_relay_set_t *set, const portillia_relay_descriptor_t *desc, time_t now) {
    if (!set || !desc) { errno = EINVAL; return -1; }
    if (now == 0) now = time(NULL);

    if (validate_descriptor_freshness(desc, now) != 0) { errno = EINVAL; return -1; }

    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    ttak_table_t *kidx = (ttak_table_t *)set->key_index;

    const char *relay_url = desc->api_https_addr ? desc->api_https_addr : "";
    portillia_relay_state_t *existing = ttak_table_get(relays, relay_url, strlen(relay_url), 0);
    portillia_relay_state_t merged = {0};
    if (existing) {
        merged.bootstrap = existing->bootstrap;
        merged.confirmed = existing->confirmed;
        merged.banned = existing->banned;
        merged.discovery_failures = existing->discovery_failures;
        merged.active_failures = existing->active_failures;
        merged.next_discovery_refresh_at = existing->next_discovery_refresh_at;
        merged.suppress_active_until = existing->suppress_active_until;
        merged.last_seen_at = existing->last_seen_at;
        merged.discovery_rtt_ms = existing->discovery_rtt_ms;
        merged.discovery_rtt_at = existing->discovery_rtt_at;
        merged.is_saturated = existing->is_saturated;
        merged.load_factor_fixed = existing->load_factor_fixed;
        merged.load_factor_at = existing->load_factor_at;
    }
    portillia_relay_descriptor_copy(&merged.descriptor, desc);
    merged.last_seen_at = now;

    /* Rollback defense */
    char *addr_lower = str_tolower_dup(desc->address ? desc->address : "");
    if (addr_lower && addr_lower[0]) {
        portillia_key_index_entry_t *prev = ttak_table_get(kidx, addr_lower, strlen(addr_lower), 0);
        if (prev && now <= prev->tombstone_until && difftime(prev->issued_at, desc->issued_at) > 0) {
            free(addr_lower);
            pthread_rwlock_unlock(&set->mu);
            errno = EACCES;
            return -1;
        }
    }
    free(addr_lower);

    portillia_relay_state_t *stored = malloc(sizeof(*stored));
    if (!stored) { pthread_rwlock_unlock(&set->mu); errno = ENOMEM; return -1; }
    *stored = merged;
    portillia_relay_descriptor_t tmp = stored->descriptor;
    memset(&stored->descriptor, 0, sizeof(stored->descriptor));
    portillia_relay_descriptor_copy(&stored->descriptor, &tmp);
    portillia_relay_descriptor_cleanup(&tmp);

    ttak_table_put(relays, strdup(relay_url), strlen(relay_url), stored, 0);

    if (desc->address && desc->address[0]) {
        char *al = str_tolower_dup(desc->address);
        portillia_key_index_entry_t *entry = malloc(sizeof(*entry));
        if (entry) {
            entry->issued_at = desc->issued_at;
            entry->tombstone_until = desc->issued_at + PORTILLIA_ANNOUNCE_MAX_VALIDITY_SEC;
            ttak_table_put(kidx, al, strlen(al), entry, 0);
        } else {
            free(al);
        }
    }

    pthread_rwlock_unlock(&set->mu);
    return 0;
}

void portillia_relay_set_record_discovery_rtt(portillia_relay_set_t *set, const char *url, double rtt_ms, time_t measured_at) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (state) {
        state->discovery_rtt_ms = rtt_ms;
        state->discovery_rtt_at = measured_at;
    }
    pthread_rwlock_unlock(&set->mu);
}

bool portillia_relay_set_record_discovery_failure(portillia_relay_set_t *set, const char *url, int recovery_failures, char **out_reason, int *out_count) {
    if (!set || !url) {
        if (out_reason) *out_reason = NULL;
        if (out_count) *out_count = 0;
        return false;
    }
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (!state) {
        pthread_rwlock_unlock(&set->mu);
        if (out_reason) *out_reason = NULL;
        if (out_count) *out_count = 0;
        return false;
    }
    state->discovery_failures++;
    int backed_off = 0;
    char *reason = NULL;
    if (recovery_failures > 0 && state->discovery_failures >= recovery_failures) {
        int over = state->discovery_failures - recovery_failures;
        if (over > 3) over = 3;
        int backoff = PORTILLIA_DEFAULT_DIRECT_RECOVERY_BACKOFF_SEC << over;
        if (backoff > PORTILLIA_MAX_DIRECT_RECOVERY_BACKOFF_SEC) backoff = PORTILLIA_MAX_DIRECT_RECOVERY_BACKOFF_SEC;
        state->next_discovery_refresh_at = time(NULL) + backoff;
        backed_off = 1;
        reason = strdup("discovery");
    }
    int count = state->discovery_failures;
    pthread_rwlock_unlock(&set->mu);
    if (out_reason) *out_reason = reason;
    if (out_count) *out_count = count;
    return backed_off;
}

bool portillia_relay_set_record_active_failure(portillia_relay_set_t *set, const char *url, int recovery_failures, char **out_reason, int *out_count) {
    if (!set || !url) {
        if (out_reason) *out_reason = NULL;
        if (out_count) *out_count = 0;
        return false;
    }
    pthread_rwlock_wrlock(&set->mu);
    ttak_table_t *relays = (ttak_table_t *)set->relays;
    portillia_relay_state_t *state = ttak_table_get(relays, url, strlen(url), 0);
    if (!state) {
        pthread_rwlock_unlock(&set->mu);
        if (out_reason) *out_reason = NULL;
        if (out_count) *out_count = 0;
        return false;
    }
    state->active_failures++;
    int backed_off = 0;
    char *reason = NULL;
    if (recovery_failures > 0 && state->active_failures >= recovery_failures) {
        int over = state->active_failures - recovery_failures;
        if (over > 3) over = 3;
        int backoff = PORTILLIA_DEFAULT_DIRECT_RECOVERY_BACKOFF_SEC << over;
        if (backoff > PORTILLIA_MAX_DIRECT_RECOVERY_BACKOFF_SEC) backoff = PORTILLIA_MAX_DIRECT_RECOVERY_BACKOFF_SEC;
        state->suppress_active_until = time(NULL) + backoff;
        backed_off = 1;
        reason = strdup("active");
    }
    int count = state->active_failures;
    pthread_rwlock_unlock(&set->mu);
    if (out_reason) *out_reason = reason;
    if (out_count) *out_count = count;
    return backed_off;
}

/* ---------- Utility ---------- */

bool portillia_relay_state_has_observed_descriptor(const portillia_relay_state_t *state) {
    return state && state->descriptor.address && state->descriptor.address[0];
}

bool portillia_relay_descriptor_has_overlay_peer(const portillia_relay_descriptor_t *desc) {
    if (!desc) return false;
    if (!desc->supports_overlay) return false;
    const char *wg = desc->wireguard_public_key ? desc->wireguard_public_key : "";
    if (!wg[0]) return false;
    if (desc->wireguard_port <= 0 || desc->wireguard_port > 65535) return false;
    return true;
}
