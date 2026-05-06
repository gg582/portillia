/** @file relay_set.c
 * @brief Relay discovery set implementation.
 */

#include <portillia/discovery/relay_set.h>
#include <portillia/utils/log.h>
#include <ttak/ht/table.h>
#include <ttak/ht/hash.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <portillia/utils/crypto.h>

/* ---------- ttak_table iteration (Swiss-table control bytes) ---------- */

#define TTAK_OCCUPIED 0x0C

typedef void (*relay_iter_fn)(const char *url, portillia_relay_state_t *state, void *arg);

static void relay_set_iterate(ttak_table_t *t, relay_iter_fn fn, void *arg) {
    if (!t || !fn) return;
    for (size_t i = 0; i < t->capacity; i++) {
        if (t->ctrls[i] == TTAK_OCCUPIED) {
            fn((const char *)t->keys[i], (portillia_relay_state_t *)t->values[i], arg);
        }
    }
}

/* ---------- String table helpers ---------- */

static uint64_t str_hash(const void *key, size_t key_len, uint64_t k0, uint64_t k1) {
    (void)k1;
    const uint8_t *data = (const uint8_t *)key;
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < key_len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= 0x100000001b3ULL;
    }
    (void)k0;
    return hash;
}

static int str_cmp(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static void str_free(void *p) {
    portillia_gc_free_later(p);
}

static ttak_table_t *str_table_create(void) {
    ttak_table_t *t = (ttak_table_t *)portillia_gc_alloc(sizeof(ttak_table_t));
    if (!t) return NULL;
    ttak_table_init(t, 64, str_hash, str_cmp, str_free, str_free);
    return t;
}

static void str_table_destroy(ttak_table_t *t) {
    if (!t) return;
    ttak_table_destroy(t, 0);
    portillia_gc_free_later(t);
}

static void str_table_put(ttak_table_t *t, const char *key, void *value) {
    if (!t || !key) return;
    char *k = portillia_gc_strdup(key);
    ttak_table_put(t, k, strlen(k) + 1, value, 0);
}

static void *str_table_get(ttak_table_t *t, const char *key) {
    if (!t || !key) return NULL;
    return ttak_table_get(t, key, strlen(key) + 1, 0);
}

static bool str_table_remove(ttak_table_t *t, const char *key) {
    if (!t || !key) return false;
    return ttak_table_remove(t, key, strlen(key) + 1, 0);
}

/* ---------- Key index helpers ---------- */

static char *str_lower_trim(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) len--;
    size_t start = 0;
    while (start < len && isspace((unsigned char)s[start])) start++;
    size_t out_len = len - start;
    char *out = (char *)portillia_gc_alloc(out_len + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < out_len; i++) {
        out[i] = (char)tolower((unsigned char)s[start + i]);
    }
    out[out_len] = '\0';
    return out;
}

/* ---------- RelayState helpers ---------- */

static void relay_state_init(portillia_relay_state_t *s, const char *url) {
    memset(s, 0, sizeof(*s));
    portillia_relay_descriptor_init(&s->descriptor);
    if (url) s->descriptor.api_https_addr = portillia_gc_strdup(url);
}

static void relay_state_cleanup(portillia_relay_state_t *s) {
    if (!s) return;
    portillia_relay_descriptor_cleanup(&s->descriptor);
}

static bool disposable_relay_state(const portillia_relay_state_t *s) {
    return !s->bootstrap && !portillia_relay_state_has_observed_descriptor(s) && !s->banned &&
           s->discovery_failures == 0 && s->active_failures == 0 &&
           s->next_discovery_refresh_at == 0 && s->suppress_active_until == 0;
}

bool portillia_relay_state_has_observed_descriptor(const portillia_relay_state_t *state) {
    return state && state->last_seen_at != 0;
}

bool portillia_relay_descriptor_has_overlay_peer(const portillia_relay_descriptor_t *desc) {
    return desc && desc->supports_overlay && desc->wireguard_public_key && desc->wireguard_public_key[0];
}

/* ---------- GF(64) MOLS core math ---------- */

#define MOLS_ORDER 64
#define MOLS_MAGIC_CONSTANT (MOLS_ORDER * MOLS_ORDER + 1)
#define MOLS_BASE_M1    3
#define MOLS_BASE_M2    5
#define MOLS_VARIANT_M1 7
#define MOLS_VARIANT_M2 11
#define MOLS_CONGESTION_RTT_MS 500.0
#define MOLS_FALLBACK_RTT_MS 2000.0
#define MOLS_CV_THRESHOLD 0.5
#define MOLS_MIN_ACTIVE_NODES 2

static uint8_t gf64_mul(uint8_t a, uint8_t b) {
    a &= 0x3f;
    b &= 0x3f;
    uint8_t r = 0;
    while (b != 0) {
        if (b & 1) r ^= a;
        if (a & 0x20) {
            a = ((a << 1) ^ 0x43) & 0x3f;
        } else {
            a = (a << 1) & 0x3f;
        }
        b >>= 1;
    }
    return r;
}

static int mols_score(uint8_t i, uint8_t j, uint8_t m1, uint8_t m2) {
    uint8_t l1 = gf64_mul(m1, i) ^ j;
    uint8_t l2 = gf64_mul(m2, i) ^ j;
    return (int)l1 * MOLS_ORDER + (int)l2 + 1;
}

static int mols_congestion_score(uint8_t i, uint8_t j, uint8_t m1, uint8_t m2) {
    return MOLS_MAGIC_CONSTANT - mols_score(i, (MOLS_ORDER - 1) - j, m1, m2);
}

static uint8_t fnv1a_hash_u8(const char *s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    while (s && *s) {
        h ^= (uint64_t)(unsigned char)*s++;
        h *= 0x100000001b3ULL;
    }
    return (uint8_t)(h & 0x3f);
}

/* ---------- Descriptor signature verification ---------- */

static void build_canonical_descriptor_json(const portillia_relay_descriptor_t *d, char *out, size_t out_len) {
    long long issued_ns = (long long)d->issued_at * 1000000000LL;
    long long expires_ns = (long long)d->expires_at * 1000000000LL;
    snprintf(
        out, out_len,
        "{\"address\":\"%s\",\"version\":\"%s\",\"issued_at_unix_nano\":%lld,\"expires_at_unix_nano\":%lld,"
        "\"api_https_addr\":\"%s\",\"wireguard_public_key\":\"%s\",\"wireguard_port\":%d,"
        "\"supports_overlay\":%s,\"supports_udp\":%s,\"supports_tcp\":%s,"
        "\"active_connections\":%lld,\"tcp_bps\":%.17g}",
        d->address ? d->address : "",
        d->version ? d->version : "",
        issued_ns,
        expires_ns,
        d->api_https_addr ? d->api_https_addr : "",
        d->wireguard_public_key ? d->wireguard_public_key : "",
        d->wireguard_port,
        d->supports_overlay ? "true" : "false",
        d->supports_udp ? "true" : "false",
        d->supports_tcp ? "true" : "false",
        (long long)d->active_connections,
        d->tcp_bps
    );
}

static int base64_decode(const char *in, uint8_t *out, size_t out_max) {
    if (!in || !out) return -1;
    BIO *bio = BIO_new_mem_buf(in, (int)strlen(in));
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded = BIO_read(bio, out, (int)out_max);
    BIO_free_all(bio);
    return decoded;
}

static bool verify_relay_descriptor(const portillia_relay_descriptor_t *desc) {
    if (!desc || !desc->signature || !desc->signature[0]) return false;
    if (!desc->address || !desc->address[0]) return false;

    uint8_t sig65[65];
    int sig_len = base64_decode(desc->signature, sig65, sizeof(sig65));
    if (sig_len != 65) return false;

    uint8_t first_byte = sig65[0];
    int recid;
    if (first_byte >= 31) recid = first_byte - 31;
    else if (first_byte >= 27) recid = first_byte - 27;
    else recid = first_byte;
    if (recid < 0 || recid > 3) return false;

    char canonical[2048];
    build_canonical_descriptor_json(desc, canonical, sizeof(canonical));
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t *)canonical, strlen(canonical), hash);

    uint8_t pub_uncompressed[65];
    if (portillia_crypto_recover_secp256k1_compact(hash, sig65 + 1, recid, pub_uncompressed) != 0) {
        return false;
    }

    char derived_addr[43] = {0};
    portillia_crypto_pubkey_to_address(pub_uncompressed, sizeof(pub_uncompressed), derived_addr);
    return strcasecmp(derived_addr, desc->address) == 0;
}

/* ---------- Validation ---------- */

static int validate_descriptor_freshness(const portillia_relay_descriptor_t *desc, time_t now) {
    if (desc->issued_at == 0) return -1;
    if (desc->expires_at <= now) return -1;
    if (desc->issued_at > now + PORTILLIA_ANNOUNCE_CLOCK_SKEW_TOLERANCE_SEC) return -1;
    if (desc->expires_at - desc->issued_at > PORTILLIA_ANNOUNCE_MAX_VALIDITY_SEC) return -1;
    return 0;
}

/* ---------- Upsert ---------- */

typedef enum {
    UPSERT_REJECTED = 0,
    UPSERT_ACCEPTED,
    UPSERT_IGNORED
} upsert_result_t;

static upsert_result_t upsert_descriptor_locked(portillia_relay_set_t *set,
                                                 const portillia_relay_state_t *record,
                                                 time_t now, bool allow_cross_identity_takeover) {
    const char *relay_url = record->descriptor.api_https_addr;
    if (!relay_url || !relay_url[0]) return UPSERT_REJECTED;

    char *address = str_lower_trim(record->descriptor.address);
    if (address && address[0]) {
        portillia_key_index_entry_t *prev = (portillia_key_index_entry_t *)str_table_get(set->key_index, address);
        if (prev) {
            if (prev->tombstone_until != 0 && now > prev->tombstone_until) {
                str_table_remove(set->key_index, address);
            } else if (record->descriptor.issued_at < prev->issued_at) {
                portillia_relay_state_t *existing = (portillia_relay_state_t *)str_table_get(set->relays, relay_url);
                if (existing) {
                    char *existing_addr = str_lower_trim(existing->descriptor.address);
                    bool same_addr = existing_addr && strcmp(existing_addr, address) == 0;
                    portillia_gc_free_later(existing_addr);
                    if (same_addr && existing->descriptor.expires_at > now &&
                        existing->descriptor.issued_at >= record->descriptor.issued_at) {
                        portillia_gc_free_later(address);
                        return UPSERT_IGNORED;
                    }
                }
                portillia_gc_free_later(address);
                return UPSERT_REJECTED;
            }
        }
    }

    if (!allow_cross_identity_takeover) {
        portillia_relay_state_t *existing = (portillia_relay_state_t *)str_table_get(set->relays, relay_url);
        if (existing) {
            char *existing_addr = str_lower_trim(existing->descriptor.address);
            bool existing_has_addr = existing_addr && existing_addr[0];
            bool record_has_addr = address && address[0];
            if (existing_has_addr && record_has_addr && strcmp(existing_addr, address) != 0) {
                if (existing->descriptor.expires_at != 0 && existing->descriptor.expires_at > now) {
                    portillia_gc_free_later(existing_addr);
                    portillia_gc_free_later(address);
                    return UPSERT_REJECTED;
                }
            }
            portillia_gc_free_later(existing_addr);
        }
    }

    portillia_relay_state_t *stored = (portillia_relay_state_t *)portillia_gc_alloc(sizeof(portillia_relay_state_t));
    if (!stored) {
        portillia_gc_free_later(address);
        return UPSERT_REJECTED;
    }
    memcpy(stored, record, sizeof(*stored));
    portillia_relay_descriptor_copy(&stored->descriptor, &record->descriptor);
    str_table_put(set->relays, relay_url, stored);

    if (address && address[0]) {
        time_t issued_at = record->descriptor.issued_at;
        time_t tombstone_until = issued_at + PORTILLIA_ANNOUNCE_MAX_VALIDITY_SEC;
        portillia_key_index_entry_t *prev = (portillia_key_index_entry_t *)str_table_get(set->key_index, address);
        if (prev) {
            if (prev->issued_at > issued_at) issued_at = prev->issued_at;
            if (prev->tombstone_until > tombstone_until) tombstone_until = prev->tombstone_until;
        }
        portillia_key_index_entry_t *entry = (portillia_key_index_entry_t *)portillia_gc_alloc(sizeof(*entry));
        entry->issued_at = issued_at;
        entry->tombstone_until = tombstone_until;
        str_table_put(set->key_index, address, entry);
    }
    portillia_gc_free_later(address);
    return UPSERT_ACCEPTED;
}

/* ---------- Capacity enforcement ---------- */

static void enforce_cap_locked(portillia_relay_set_t *set) {
    time_t now = time(NULL);
    if (!set || !set->key_index) return;
    ttak_table_t *t = (ttak_table_t *)set->key_index;
    for (size_t i = 0; i < t->capacity; i++) {
        if (t->ctrls[i] == TTAK_OCCUPIED) {
            portillia_key_index_entry_t *entry = (portillia_key_index_entry_t *)t->values[i];
            if (entry && entry->tombstone_until > 0 && entry->tombstone_until < now) {
                str_table_remove(set->key_index, (const char *)t->keys[i]);
            }
        }
    }
}

/* ---------- Public API ---------- */

portillia_relay_set_t *portillia_relay_set_create(const char **bootstrap_urls, size_t count) {
    portillia_relay_set_t *set = PORTILLIA_GC_NEW_ZERO(portillia_relay_set_t);
    if (!set) return NULL;
    pthread_rwlock_init(&set->mu, NULL);
    set->relays = str_table_create();
    set->key_index = str_table_create();
    if (count > 0 && bootstrap_urls) {
        portillia_relay_set_set_bootstrap_urls(set, bootstrap_urls, count);
    }
    return set;
}

void portillia_relay_set_free(portillia_relay_set_t *set) {
    if (!set) return;
    pthread_rwlock_wrlock(&set->mu);
    str_table_destroy((ttak_table_t *)set->relays);
    str_table_destroy((ttak_table_t *)set->key_index);
    pthread_rwlock_unlock(&set->mu);
    pthread_rwlock_destroy(&set->mu);
    portillia_gc_free_later(set);
}

static void clear_bootstrap_cb(const char *url, portillia_relay_state_t *state, void *arg) {
    (void)url;
    (void)arg;
    if (state) state->bootstrap = false;
}

void portillia_relay_set_set_bootstrap_urls(portillia_relay_set_t *set, const char **urls, size_t count) {
    if (!set) return;
    pthread_rwlock_wrlock(&set->mu);
    relay_set_iterate((ttak_table_t *)set->relays, clear_bootstrap_cb, NULL);
    pthread_rwlock_unlock(&set->mu);
    for (size_t i = 0; i < count; i++) {
        portillia_relay_set_add_bootstrap_url(set, urls[i]);
    }
}

void portillia_relay_set_add_bootstrap_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    if (!state) {
        portillia_relay_state_t tmp;
        relay_state_init(&tmp, url);
        tmp.bootstrap = true;
        portillia_relay_state_t *stored = (portillia_relay_state_t *)portillia_gc_alloc(sizeof(*stored));
        memcpy(stored, &tmp, sizeof(tmp));
        str_table_put(set->relays, url, stored);
    } else {
        state->bootstrap = true;
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_remove_bootstrap_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    if (state) {
        state->bootstrap = false;
        if (disposable_relay_state(state)) {
            str_table_remove(set->relays, url);
        }
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_ban_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    if (!state) {
        portillia_relay_state_t tmp;
        relay_state_init(&tmp, url);
        tmp.banned = true;
        portillia_relay_state_t *stored = (portillia_relay_state_t *)portillia_gc_alloc(sizeof(*stored));
        memcpy(stored, &tmp, sizeof(tmp));
        str_table_put(set->relays, url, stored);
    } else {
        state->banned = true;
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_allow_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    if (!state) {
        portillia_relay_state_t tmp;
        relay_state_init(&tmp, url);
        portillia_relay_state_t *stored = (portillia_relay_state_t *)portillia_gc_alloc(sizeof(*stored));
        memcpy(stored, &tmp, sizeof(tmp));
        str_table_put(set->relays, url, stored);
    } else {
        state->banned = false;
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_confirm_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    if (!state) {
        portillia_relay_state_t tmp;
        relay_state_init(&tmp, url);
        tmp.confirmed = true;
        portillia_relay_state_t *stored = (portillia_relay_state_t *)portillia_gc_alloc(sizeof(*stored));
        memcpy(stored, &tmp, sizeof(tmp));
        str_table_put(set->relays, url, stored);
    } else {
        state->confirmed = true;
    }
    pthread_rwlock_unlock(&set->mu);
}

void portillia_relay_set_unconfirm_url(portillia_relay_set_t *set, const char *url) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    if (state) {
        state->confirmed = false;
    }
    pthread_rwlock_unlock(&set->mu);
}

typedef struct {
    portillia_relay_state_t *states;
    size_t count;
    size_t cap;
} relay_collect_ctx_t;

static void collect_all_cb(const char *url, portillia_relay_state_t *state, void *arg) {
    (void)url;
    relay_collect_ctx_t *ctx = (relay_collect_ctx_t *)arg;
    if (!ctx || !state) return;
    if (ctx->count >= ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 16;
        portillia_relay_state_t *next = (portillia_relay_state_t *)portillia_gc_realloc(ctx->states, sizeof(*ctx->states) * new_cap);
        if (!next) return;
        ctx->states = next;
        ctx->cap = new_cap;
    }
    portillia_relay_state_t *slot = &ctx->states[ctx->count++];
    memcpy(slot, state, sizeof(*state));
    portillia_relay_descriptor_init(&slot->descriptor);
    portillia_relay_descriptor_copy(&slot->descriptor, &state->descriptor);
}

size_t portillia_relay_set_all_relays(portillia_relay_set_t *set, portillia_relay_state_t **out_states) {
    if (!set || !out_states) return 0;
    relay_collect_ctx_t ctx = {0};
    pthread_rwlock_rdlock(&set->mu);
    relay_set_iterate((ttak_table_t *)set->relays, collect_all_cb, &ctx);
    pthread_rwlock_unlock(&set->mu);
    *out_states = ctx.states;
    return ctx.count;
}

static void collect_confirmed_cb(const char *url, portillia_relay_state_t *state, void *arg) {
    (void)url;
    relay_collect_ctx_t *ctx = (relay_collect_ctx_t *)arg;
    if (!ctx || !state || !state->confirmed || state->banned) return;
    if (ctx->count >= ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 16;
        portillia_relay_state_t *next = (portillia_relay_state_t *)portillia_gc_realloc(ctx->states, sizeof(*ctx->states) * new_cap);
        if (!next) return;
        ctx->states = next;
        ctx->cap = new_cap;
    }
    portillia_relay_state_t *slot = &ctx->states[ctx->count++];
    memcpy(slot, state, sizeof(*state));
    portillia_relay_descriptor_init(&slot->descriptor);
    portillia_relay_descriptor_copy(&slot->descriptor, &state->descriptor);
}

size_t portillia_relay_set_confirmed_relays(portillia_relay_set_t *set, portillia_relay_state_t **out_states) {
    if (!set || !out_states) return 0;
    relay_collect_ctx_t ctx = {0};
    pthread_rwlock_rdlock(&set->mu);
    relay_set_iterate((ttak_table_t *)set->relays, collect_confirmed_cb, &ctx);
    pthread_rwlock_unlock(&set->mu);
    *out_states = ctx.states;
    return ctx.count;
}

typedef struct {
    portillia_relay_state_t *state;
    char *url;
    int score;
    bool fallback;
} relay_sort_entry_t;

static int cmp_rtt_asc(const void *a, const void *b) {
    const relay_sort_entry_t *ea = (const relay_sort_entry_t *)a;
    const relay_sort_entry_t *eb = (const relay_sort_entry_t *)b;
    double da = ea->state ? ea->state->discovery_rtt_ms : 0;
    double db = eb->state ? eb->state->discovery_rtt_ms : 0;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static int cmp_mols_desc(const void *a, const void *b) {
    const relay_sort_entry_t *ea = (const relay_sort_entry_t *)a;
    const relay_sort_entry_t *eb = (const relay_sort_entry_t *)b;
    if (!ea->fallback && eb->fallback) return -1;
    if (ea->fallback && !eb->fallback) return 1;
    if (ea->score > eb->score) return -1;
    if (ea->score < eb->score) return 1;
    if (ea->state && eb->state) {
        if (ea->state->confirmed && !eb->state->confirmed) return -1;
        if (!ea->state->confirmed && eb->state->confirmed) return 1;
        double da = ea->state->discovery_rtt_ms;
        double db = eb->state->discovery_rtt_ms;
        if (da < db) return -1;
        if (da > db) return 1;
    }
    return strcmp(ea->url, eb->url);
}

static void rank_relay_pool_mols(relay_sort_entry_t *pool, size_t count, const char *local_address) {
    if (count == 0) return;
    uint8_t i = fnv1a_hash_u8(local_address && local_address[0] ? local_address : "127.0.0.1");

    double sum_rtt = 0;
    size_t rtt_count = 0;
    for (size_t k = 0; k < count; k++) {
        if (pool[k].state && pool[k].state->discovery_rtt_ms > 0) {
            sum_rtt += pool[k].state->discovery_rtt_ms;
            rtt_count++;
        }
    }
    double mean_rtt = rtt_count > 0 ? sum_rtt / rtt_count : 0;
    double variance = 0;
    for (size_t k = 0; k < count; k++) {
        if (pool[k].state && pool[k].state->discovery_rtt_ms > 0) {
            double diff = pool[k].state->discovery_rtt_ms - mean_rtt;
            variance += diff * diff;
        }
    }
    double stddev = rtt_count > 0 ? sqrt(variance / rtt_count) : 0;
    double cv = mean_rtt > 0 ? stddev / mean_rtt : 0;

    bool congested = mean_rtt > MOLS_CONGESTION_RTT_MS;
    bool non_linear = cv > MOLS_CV_THRESHOLD && count >= MOLS_MIN_ACTIVE_NODES;
    uint8_t m1 = non_linear ? MOLS_VARIANT_M1 : MOLS_BASE_M1;
    uint8_t m2 = non_linear ? MOLS_VARIANT_M2 : MOLS_BASE_M2;

    for (size_t k = 0; k < count; k++) {
        uint8_t j = fnv1a_hash_u8(pool[k].url);
        if (congested) {
            pool[k].score = mols_congestion_score(i, j, m1, m2);
        } else {
            pool[k].score = mols_score(i, j, m1, m2);
        }
        pool[k].fallback = pool[k].state && pool[k].state->discovery_rtt_ms > MOLS_FALLBACK_RTT_MS;
    }
    qsort(pool, count, sizeof(*pool), cmp_mols_desc);
}

static bool string_in_array(const char *s, char **arr, size_t count) {
    if (!s || !arr) return false;
    for (size_t i = 0; i < count; i++) {
        if (arr[i] && strcmp(s, arr[i]) == 0) return true;
    }
    return false;
}

char **portillia_relay_set_priority_relays(portillia_relay_set_t *set, const portillia_client_state_t *client, size_t *out_count) {
    if (!set || !client || !out_count) return NULL;
    *out_count = 0;

    size_t cap = 64;
    relay_sort_entry_t *pool = (relay_sort_entry_t *)portillia_gc_alloc(sizeof(*pool) * cap);
    size_t pool_count = 0;
    time_t now = time(NULL);

    pthread_rwlock_rdlock(&set->mu);

    /* Collect all non-banned states */
    ttak_table_t *t = (ttak_table_t *)set->relays;
    for (size_t i = 0; i < t->capacity; i++) {
        if (t->ctrls[i] != TTAK_OCCUPIED) continue;
        portillia_relay_state_t *state = (portillia_relay_state_t *)t->values[i];
        const char *url = (const char *)t->keys[i];
        if (!state || state->banned) continue;
        if (pool_count >= cap) {
            cap *= 2;
            pool = (relay_sort_entry_t *)portillia_gc_realloc(pool, sizeof(*pool) * cap);
        }
        pool[pool_count].state = state;
        pool[pool_count].url = (char *)url;
        pool_count++;
    }
    pthread_rwlock_unlock(&set->mu);

    /* Separate explicit and auto */
    char **explicit_urls = (char **)portillia_gc_alloc(sizeof(char *) * pool_count);
    relay_sort_entry_t *auto_pool = (relay_sort_entry_t *)portillia_gc_alloc(sizeof(*auto_pool) * pool_count);
    size_t explicit_count = 0;
    size_t auto_count = 0;

    for (size_t i = 0; i < pool_count; i++) {
        const char *url = pool[i].url;
        portillia_relay_state_t *state = pool[i].state;
        bool is_explicit = string_in_array(url, client->explicit_relay_urls, client->explicit_relay_urls_count);
        bool is_suppressed = string_in_array(url, client->suppressed_relay_urls, client->suppressed_relay_urls_count);

        if (is_explicit) {
            if (state && portillia_relay_state_has_observed_descriptor(state) && state->descriptor.expires_at > now) {
                if (client->require_udp && !state->descriptor.supports_udp) continue;
                if (client->require_tcp && !state->descriptor.supports_tcp) continue;
            }
            explicit_urls[explicit_count++] = portillia_gc_strdup(url);
            continue;
        }
        if (is_suppressed) continue;
        if (!state->confirmed) continue;
        if (portillia_relay_state_has_observed_descriptor(state) && state->descriptor.expires_at <= now) continue;
        if (client->require_udp && portillia_relay_state_has_observed_descriptor(state) && !state->descriptor.supports_udp) continue;
        if (client->require_tcp && portillia_relay_state_has_observed_descriptor(state) && !state->descriptor.supports_tcp) continue;
        if (state->suppress_active_until > 0 && state->suppress_active_until > now) continue;

        auto_pool[auto_count].state = state;
        auto_pool[auto_count].url = (char *)url;
        auto_count++;
    }

    /* Sort auto pool by RTT ascending */
    if (auto_count > 1) {
        qsort(auto_pool, auto_count, sizeof(*auto_pool), cmp_rtt_asc);
    }

    int max_active = client->max_active_relays > 0 ? client->max_active_relays : 4;
    size_t total = explicit_count;
    size_t auto_take = auto_count;
    if ((int)(explicit_count + auto_take) > max_active) {
        auto_take = (size_t)max_active > explicit_count ? (size_t)max_active - explicit_count : 0;
    }
    total += auto_take;

    char **result = (char **)portillia_gc_alloc(sizeof(char *) * total);
    size_t idx = 0;
    for (size_t i = 0; i < explicit_count; i++) result[idx++] = explicit_urls[i];
    for (size_t i = 0; i < auto_take; i++) result[idx++] = portillia_gc_strdup(auto_pool[i].url);

    *out_count = idx;
    return result;
}

char **portillia_relay_set_priority_multi_hop(portillia_relay_set_t *set, const portillia_client_state_t *client, size_t *out_count) {
    if (!set || !client || !out_count) return NULL;
    *out_count = 0;
    if (client->multi_hop_depth <= 1) return NULL;

    size_t cap = 64;
    relay_sort_entry_t *pool = (relay_sort_entry_t *)portillia_gc_alloc(sizeof(*pool) * cap);
    size_t pool_count = 0;
    time_t now = time(NULL);

    pthread_rwlock_rdlock(&set->mu);
    ttak_table_t *t = (ttak_table_t *)set->relays;
    for (size_t i = 0; i < t->capacity; i++) {
        if (t->ctrls[i] != TTAK_OCCUPIED) continue;
        portillia_relay_state_t *state = (portillia_relay_state_t *)t->values[i];
        const char *url = (const char *)t->keys[i];
        if (!state || state->banned) continue;
        if (string_in_array(url, client->suppressed_relay_urls, client->suppressed_relay_urls_count)) continue;
        if (client->require_udp && portillia_relay_state_has_observed_descriptor(state) && !state->descriptor.supports_udp) continue;
        if (client->require_tcp && portillia_relay_state_has_observed_descriptor(state) && !state->descriptor.supports_tcp) continue;
        if (!portillia_relay_state_has_observed_descriptor(state) || state->descriptor.expires_at <= now || !portillia_relay_descriptor_has_overlay_peer(&state->descriptor)) continue;
        if (state->suppress_active_until > 0 && state->suppress_active_until > now) continue;
        if (pool_count >= cap) {
            cap *= 2;
            pool = (relay_sort_entry_t *)portillia_gc_realloc(pool, sizeof(*pool) * cap);
        }
        pool[pool_count].state = state;
        pool[pool_count].url = (char *)url;
        pool_count++;
    }
    pthread_rwlock_unlock(&set->mu);

    if (pool_count == 0) return NULL;
    rank_relay_pool_mols(pool, pool_count, client->local_address);

    size_t take = (size_t)client->multi_hop_depth;
    if (take > pool_count) take = pool_count;

    char **result = (char **)portillia_gc_alloc(sizeof(char *) * take);
    for (size_t i = 0; i < take; i++) {
        result[i] = portillia_gc_strdup(pool[i].url);
    }
    *out_count = take;
    return result;
}

static void collect_overlay_cb(const char *url, portillia_relay_state_t *state, void *arg) {
    (void)url;
    relay_collect_ctx_t *ctx = (relay_collect_ctx_t *)arg;
    if (!ctx || !state || state->banned) return;
    if (!portillia_relay_state_has_observed_descriptor(state)) return;
    if (!portillia_relay_descriptor_has_overlay_peer(&state->descriptor)) return;
    if (ctx->count >= ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 16;
        portillia_relay_state_t *next = (portillia_relay_state_t *)portillia_gc_realloc(ctx->states, sizeof(*ctx->states) * new_cap);
        if (!next) return;
        ctx->states = next;
        ctx->cap = new_cap;
    }
    portillia_relay_state_t *slot = &ctx->states[ctx->count++];
    memcpy(slot, state, sizeof(*state));
    portillia_relay_descriptor_init(&slot->descriptor);
    portillia_relay_descriptor_copy(&slot->descriptor, &state->descriptor);
}

size_t portillia_relay_set_overlay_peers(portillia_relay_set_t *set, portillia_relay_state_t **out_states) {
    if (!set || !out_states) return 0;
    relay_collect_ctx_t ctx = {0};
    pthread_rwlock_rdlock(&set->mu);
    relay_set_iterate((ttak_table_t *)set->relays, collect_overlay_cb, &ctx);
    pthread_rwlock_unlock(&set->mu);
    *out_states = ctx.states;
    return ctx.count;
}

bool portillia_relay_set_overlay_descriptor(portillia_relay_set_t *set, const char *relay_url, time_t now, portillia_relay_descriptor_t *out_desc) {
    if (!set || !relay_url || !out_desc) return false;
    pthread_rwlock_rdlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, relay_url);
    bool ok = false;
    if (state && !state->banned && portillia_relay_state_has_observed_descriptor(state) &&
        state->descriptor.expires_at > now && portillia_relay_descriptor_has_overlay_peer(&state->descriptor)) {
        portillia_relay_descriptor_copy(out_desc, &state->descriptor);
        ok = true;
    }
    pthread_rwlock_unlock(&set->mu);
    return ok;
}

typedef struct {
    char **urls;
    size_t count;
    size_t cap;
} url_collect_ctx_t;

static void collect_bootstrap_urls_cb(const char *url, portillia_relay_state_t *state, void *arg) {
    url_collect_ctx_t *ctx = (url_collect_ctx_t *)arg;
    if (!ctx || !state || !state->bootstrap || !url) return;
    if (ctx->count >= ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 16;
        char **next = (char **)portillia_gc_realloc(ctx->urls, sizeof(*ctx->urls) * new_cap);
        if (!next) return;
        ctx->urls = next;
        ctx->cap = new_cap;
    }
    ctx->urls[ctx->count++] = portillia_gc_strdup(url);
}

size_t portillia_relay_set_bootstrap_urls(portillia_relay_set_t *set, char ***out_urls) {
    if (!set || !out_urls) return 0;
    url_collect_ctx_t ctx = {0};
    pthread_rwlock_rdlock(&set->mu);
    relay_set_iterate((ttak_table_t *)set->relays, collect_bootstrap_urls_cb, &ctx);
    pthread_rwlock_unlock(&set->mu);
    *out_urls = ctx.urls;
    return ctx.count;
}

typedef struct {
    portillia_relay_descriptor_t *descs;
    size_t count;
    size_t cap;
} desc_collect_ctx_t;

static void collect_descriptors_cb(const char *url, portillia_relay_state_t *state, void *arg) {
    (void)url;
    desc_collect_ctx_t *ctx = (desc_collect_ctx_t *)arg;
    if (!ctx || !state) return;
    if (!portillia_relay_state_has_observed_descriptor(state)) return;
    if (!state->descriptor.signature || !state->descriptor.signature[0]) return;
    if (ctx->count >= ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 16;
        portillia_relay_descriptor_t *next = (portillia_relay_descriptor_t *)portillia_gc_realloc(ctx->descs, sizeof(*ctx->descs) * new_cap);
        if (!next) return;
        ctx->descs = next;
        ctx->cap = new_cap;
    }
    portillia_relay_descriptor_t *slot = &ctx->descs[ctx->count++];
    portillia_relay_descriptor_init(slot);
    portillia_relay_descriptor_copy(slot, &state->descriptor);
}

size_t portillia_relay_set_descriptors(portillia_relay_set_t *set, const portillia_relay_descriptor_t *self, portillia_relay_descriptor_t **out_descs) {
    (void)self;
    if (!set || !out_descs) return 0;
    desc_collect_ctx_t ctx = {0};
    pthread_rwlock_rdlock(&set->mu);
    relay_set_iterate((ttak_table_t *)set->relays, collect_descriptors_cb, &ctx);
    pthread_rwlock_unlock(&set->mu);
    *out_descs = ctx.descs;
    return ctx.count;
}

/* verify_relay_descriptor implemented above in the Descriptor signature verification section */

int portillia_relay_set_apply_discovery_response(portillia_relay_set_t *set, const char *target_url,
                                                  const portillia_discovery_response_t *resp, time_t now,
                                                  bool *out_changed) {
    if (!set || !resp) { errno = EINVAL; return -1; }
    if (out_changed) *out_changed = false;

    bool protocol_mismatch = false;
    if (resp->protocol_version && strcmp(resp->protocol_version, PORTILLIA_DISCOVERY_VERSION) != 0) {
        protocol_mismatch = true;
    }
    bool authoritative = target_url && target_url[0];
    bool changed = false;
    bool target_found = false;

    pthread_rwlock_wrlock(&set->mu);

    for (size_t i = 0; i < resp->relays_count; i++) {
        portillia_relay_descriptor_t *desc = &resp->relays[i];
        if (!verify_relay_descriptor(desc)) continue;
        if (validate_descriptor_freshness(desc, now) != 0) continue;
        const char *relay_url = desc->api_https_addr;
        if (!relay_url || !relay_url[0]) continue;
        if (authoritative && strcmp(relay_url, target_url) == 0) target_found = true;

        portillia_relay_state_t record;
        relay_state_init(&record, relay_url);
        portillia_relay_descriptor_copy(&record.descriptor, desc);
        record.last_seen_at = now;

        /* Merge existing local telemetry */
        portillia_relay_state_t *existing = (portillia_relay_state_t *)str_table_get(set->relays, relay_url);
        if (existing) {
            record.bootstrap = record.bootstrap || existing->bootstrap;
            record.confirmed = record.confirmed || existing->confirmed;
            record.banned = record.banned || existing->banned;
            if (record.discovery_failures < existing->discovery_failures) record.discovery_failures = existing->discovery_failures;
            if (record.active_failures < existing->active_failures) record.active_failures = existing->active_failures;
            record.next_discovery_refresh_at = existing->next_discovery_refresh_at;
            record.suppress_active_until = existing->suppress_active_until;
            if (record.discovery_rtt_at == 0 || (existing->discovery_rtt_at != 0 && existing->discovery_rtt_at > record.discovery_rtt_at)) {
                record.discovery_rtt_ms = existing->discovery_rtt_ms;
                record.discovery_rtt_at = existing->discovery_rtt_at;
            }
        }

        bool is_authoritative_target = !protocol_mismatch && (!authoritative || target_found) && authoritative && strcmp(relay_url, target_url) == 0;
        if (is_authoritative_target) {
            record.discovery_failures = 0;
            record.next_discovery_refresh_at = 0;
        }

        int upsert = upsert_descriptor_locked(set, &record, now, is_authoritative_target);
        if (upsert == 0) {
            changed = true;
        }
        relay_state_cleanup(&record);
    }

    pthread_rwlock_unlock(&set->mu);
    if (out_changed) *out_changed = changed;
    return 0;
}

int portillia_relay_set_insert_announced(portillia_relay_set_t *set, const portillia_relay_descriptor_t *desc, time_t now) {
    if (!set || !desc) { errno = EINVAL; return -1; }

    if (!verify_relay_descriptor(desc)) {
        errno = EACCES;
        return -1;
    }
    if (validate_descriptor_freshness(desc, now) != 0) {
        errno = EBADMSG;
        return -1;
    }

    portillia_relay_state_t record;
    relay_state_init(&record, desc->api_https_addr);
    portillia_relay_descriptor_copy(&record.descriptor, desc);
    record.last_seen_at = now;

    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *existing = (portillia_relay_state_t *)str_table_get(set->relays, desc->api_https_addr);
    if (existing) {
        record.bootstrap = record.bootstrap || existing->bootstrap;
        record.confirmed = record.confirmed || existing->confirmed;
        record.banned = record.banned || existing->banned;
        if (record.discovery_failures < existing->discovery_failures)
            record.discovery_failures = existing->discovery_failures;
        if (record.active_failures < existing->active_failures)
            record.active_failures = existing->active_failures;
        record.next_discovery_refresh_at = existing->next_discovery_refresh_at;
        record.suppress_active_until = existing->suppress_active_until;
        if (record.discovery_rtt_at == 0 || (existing->discovery_rtt_at != 0 && existing->discovery_rtt_at > record.discovery_rtt_at)) {
            record.discovery_rtt_ms = existing->discovery_rtt_ms;
            record.discovery_rtt_at = existing->discovery_rtt_at;
        }
    }

    upsert_result_t res = upsert_descriptor_locked(set, &record, now, false);
    pthread_rwlock_unlock(&set->mu);
    portillia_relay_descriptor_cleanup(&record.descriptor);

    if (res == UPSERT_ACCEPTED) {
        pthread_rwlock_wrlock(&set->mu);
        enforce_cap_locked(set);
        pthread_rwlock_unlock(&set->mu);
        return 0;
    } else if (res == UPSERT_IGNORED) {
        return 0;
    }
    errno = EBADMSG;
    return -1;
}

void portillia_relay_set_record_discovery_rtt(portillia_relay_set_t *set, const char *url, double rtt_ms, time_t measured_at) {
    if (!set || !url) return;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    if (state) {
        state->discovery_rtt_ms = rtt_ms;
        state->discovery_rtt_at = measured_at;
    }
    pthread_rwlock_unlock(&set->mu);
}

bool portillia_relay_set_record_discovery_failure(portillia_relay_set_t *set, const char *url, int recovery_failures, char **out_reason, int *out_count) {
    if (!set || !url) return false;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    bool backed_off = false;
    if (state) {
        state->discovery_failures++;
        (void)recovery_failures;
        if (out_count) *out_count = state->discovery_failures;
    }
    pthread_rwlock_unlock(&set->mu);
    if (out_reason) *out_reason = NULL;
    return backed_off;
}

bool portillia_relay_set_record_active_failure(portillia_relay_set_t *set, const char *url, int recovery_failures, char **out_reason, int *out_count) {
    if (!set || !url) return false;
    pthread_rwlock_wrlock(&set->mu);
    portillia_relay_state_t *state = (portillia_relay_state_t *)str_table_get(set->relays, url);
    bool backed_off = false;
    if (state) {
        state->active_failures++;
        (void)recovery_failures;
        if (out_count) *out_count = state->active_failures;
    }
    pthread_rwlock_unlock(&set->mu);
    if (out_reason) *out_reason = NULL;
    return backed_off;
}
