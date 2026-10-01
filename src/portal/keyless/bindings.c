#include <portillia/portal/keyless/bindings.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

/* ------------------------------------------------------------------ */
/* Binding registry (bindings.go BindingRegistry).                    */
/* ------------------------------------------------------------------ */

typedef struct portillia_binding_entry {
    uint8_t binding[PORTILLIA_BINDING_SIZE];
    char *lease_id;
    struct timespec expires_at;
    uint8_t hello_hash[PORTILLIA_BINDING_HELLO_HASH_SIZE]; /* all-zero = unfixed */
    struct portillia_binding_entry *next;
} portillia_binding_entry;

struct portillia_binding_registry {
    pthread_mutex_t mu;
    portillia_binding_entry **buckets;
    size_t bucket_count;
    uint64_t ttl_seconds;
};

#define PORTILLIA_BINDING_BUCKETS 256

static size_t binding_bucket(const uint8_t binding[PORTILLIA_BINDING_SIZE]) {
    uint64_t h = 0;
    for (int i = 0; i < PORTILLIA_BINDING_SIZE; i++) h = (h * 1099511628211ULL) ^ binding[i];
    return (size_t)(h % PORTILLIA_BINDING_BUCKETS);
}

static bool binding_hash_is_zero(const uint8_t hash[PORTILLIA_BINDING_HELLO_HASH_SIZE]) {
    for (int i = 0; i < PORTILLIA_BINDING_HELLO_HASH_SIZE; i++) {
        if (hash[i] != 0) return false;
    }
    return true;
}

static bool timespec_before(struct timespec a, struct timespec b) {
    if (a.tv_sec != b.tv_sec) return a.tv_sec < b.tv_sec;
    return a.tv_nsec < b.tv_nsec;
}

portillia_binding_registry *portillia_bindings_new(uint64_t ttl_seconds) {
    portillia_binding_registry *reg = calloc(1, sizeof(*reg));
    if (!reg) return NULL;
    reg->buckets = calloc(PORTILLIA_BINDING_BUCKETS, sizeof(*reg->buckets));
    if (!reg->buckets) { free(reg); return NULL; }
    reg->bucket_count = PORTILLIA_BINDING_BUCKETS;
    reg->ttl_seconds = ttl_seconds;
    pthread_mutex_init(&reg->mu, NULL);
    return reg;
}

void portillia_bindings_free(portillia_binding_registry *reg) {
    if (!reg) return;
    pthread_mutex_lock(&reg->mu);
    for (size_t i = 0; i < reg->bucket_count; i++) {
        portillia_binding_entry *e = reg->buckets[i];
        while (e) {
            portillia_binding_entry *next = e->next;
            free(e->lease_id);
            free(e);
            e = next;
        }
    }
    pthread_mutex_unlock(&reg->mu);
    pthread_mutex_destroy(&reg->mu);
    free(reg->buckets);
    free(reg);
}

static portillia_binding_registry *g_shared = NULL;
static pthread_mutex_t g_shared_mu = PTHREAD_MUTEX_INITIALIZER;

portillia_binding_registry *portillia_bindings_shared(void) {
    pthread_mutex_lock(&g_shared_mu);
    if (!g_shared) g_shared = portillia_bindings_new(300);
    pthread_mutex_unlock(&g_shared_mu);
    return g_shared;
}

void portillia_bindings_issue(portillia_binding_registry *reg,
                              const char *lease_id,
                              const uint8_t *client_hello, size_t client_hello_len,
                              uint8_t out_binding[PORTILLIA_BINDING_SIZE]) {
    if (!reg || !out_binding) return;
    if (RAND_bytes(out_binding, PORTILLIA_BINDING_SIZE) != 1) {
        /* mirrors the Go panic on rand failure */
        fprintf(stderr, "issue lease binding: RAND_bytes failed\n");
        abort();
    }

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    portillia_binding_entry *e = calloc(1, sizeof(*e));
    if (!e) return;
    memcpy(e->binding, out_binding, PORTILLIA_BINDING_SIZE);
    e->lease_id = strdup(lease_id ? lease_id : "");
    e->expires_at = now;
    e->expires_at.tv_sec += (time_t)reg->ttl_seconds;
    if (client_hello && client_hello_len > 0) {
        SHA256(client_hello, client_hello_len, e->hello_hash);
    }

    pthread_mutex_lock(&reg->mu);
    size_t idx = binding_bucket(e->binding);
    e->next = reg->buckets[idx];
    reg->buckets[idx] = e;
    pthread_mutex_unlock(&reg->mu);
}

portillia_binding_status portillia_bindings_fix_hello(portillia_binding_registry *reg,
                                                      const uint8_t binding[PORTILLIA_BINDING_SIZE],
                                                      const uint8_t *client_hello, size_t client_hello_len) {
    if (!reg || !binding) return PORTILLIA_BINDING_ERR_UNKNOWN;
    if (!client_hello || client_hello_len == 0) return PORTILLIA_BINDING_ERR_HELLO_REQUIRED;

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    pthread_mutex_lock(&reg->mu);
    size_t idx = binding_bucket(binding);
    portillia_binding_entry *e = reg->buckets[idx];
    while (e && memcmp(e->binding, binding, PORTILLIA_BINDING_SIZE) != 0) e = e->next;
    if (!e) {
        pthread_mutex_unlock(&reg->mu);
        return PORTILLIA_BINDING_ERR_UNKNOWN;
    }
    if (!timespec_before(now, e->expires_at)) {
        pthread_mutex_unlock(&reg->mu);
        return PORTILLIA_BINDING_ERR_EXPIRED;
    }
    if (!binding_hash_is_zero(e->hello_hash)) {
        pthread_mutex_unlock(&reg->mu);
        return PORTILLIA_BINDING_ERR_ALREADY_FIXED;
    }
    SHA256(client_hello, client_hello_len, e->hello_hash);
    pthread_mutex_unlock(&reg->mu);
    return PORTILLIA_BINDING_OK;
}

portillia_binding_status portillia_bindings_validate_and_consume(portillia_binding_registry *reg,
                                                                 const uint8_t *binding, size_t binding_len,
                                                                 const char *lease_id,
                                                                 const uint8_t *client_hello, size_t client_hello_len) {
    if (binding_len != PORTILLIA_BINDING_SIZE) return PORTILLIA_BINDING_ERR_BAD_SIZE;
    if (!client_hello || client_hello_len == 0) return PORTILLIA_BINDING_ERR_HELLO_REQUIRED;

    uint8_t hello_hash[PORTILLIA_BINDING_HELLO_HASH_SIZE];
    SHA256(client_hello, client_hello_len, hello_hash);

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    pthread_mutex_lock(&reg->mu);
    size_t idx = binding_bucket(binding);
    portillia_binding_entry *e = reg->buckets[idx];
    portillia_binding_entry *prev = NULL;
    while (e && memcmp(e->binding, binding, PORTILLIA_BINDING_SIZE) != 0) {
        prev = e;
        e = e->next;
    }
    portillia_binding_status status = PORTILLIA_BINDING_OK;
    if (!e || !timespec_before(now, e->expires_at)) {
        status = PORTILLIA_BINDING_ERR_UNKNOWN_OR_EXPIRED;
    } else if (strcmp(e->lease_id, lease_id ? lease_id : "") != 0) {
        status = PORTILLIA_BINDING_ERR_WRONG_LEASE;
    } else if (binding_hash_is_zero(e->hello_hash)) {
        status = PORTILLIA_BINDING_ERR_NEVER_FIXED;
    } else if (memcmp(e->hello_hash, hello_hash, PORTILLIA_BINDING_HELLO_HASH_SIZE) != 0) {
        status = PORTILLIA_BINDING_ERR_HELLO_MISMATCH;
    } else {
        /* single use: spend the binding */
        if (prev) prev->next = e->next;
        else reg->buckets[idx] = e->next;
        free(e->lease_id);
        free(e);
        e = NULL;
    }
    pthread_mutex_unlock(&reg->mu);
    return status;
}

void portillia_bindings_discard(portillia_binding_registry *reg,
                                const uint8_t binding[PORTILLIA_BINDING_SIZE]) {
    if (!reg || !binding) return;
    pthread_mutex_lock(&reg->mu);
    size_t idx = binding_bucket(binding);
    portillia_binding_entry *e = reg->buckets[idx];
    portillia_binding_entry *prev = NULL;
    while (e && memcmp(e->binding, binding, PORTILLIA_BINDING_SIZE) != 0) {
        prev = e;
        e = e->next;
    }
    if (e) {
        if (prev) prev->next = e->next;
        else reg->buckets[idx] = e->next;
        free(e->lease_id);
        free(e);
    }
    pthread_mutex_unlock(&reg->mu);
}

void portillia_bindings_sweep_expired(portillia_binding_registry *reg, struct timespec now) {
    if (!reg) return;
    pthread_mutex_lock(&reg->mu);
    for (size_t i = 0; i < reg->bucket_count; i++) {
        portillia_binding_entry *e = reg->buckets[i];
        portillia_binding_entry *prev = NULL;
        while (e) {
            portillia_binding_entry *next = e->next;
            if (!timespec_before(now, e->expires_at)) {
                if (prev) prev->next = next;
                else reg->buckets[i] = next;
                free(e->lease_id);
                free(e);
            } else {
                prev = e;
            }
            e = next;
        }
    }
    pthread_mutex_unlock(&reg->mu);
}

const char *portillia_binding_strerror(portillia_binding_status status) {
    switch (status) {
        case PORTILLIA_BINDING_OK: return "ok";
        case PORTILLIA_BINDING_ERR_HELLO_REQUIRED: return "client hello is required";
        case PORTILLIA_BINDING_ERR_UNKNOWN: return "binding is unknown";
        case PORTILLIA_BINDING_ERR_EXPIRED: return "binding is expired";
        case PORTILLIA_BINDING_ERR_ALREADY_FIXED: return "binding hello is already fixed";
        case PORTILLIA_BINDING_ERR_BAD_SIZE: return "binding must be 16 bytes";
        case PORTILLIA_BINDING_ERR_UNKNOWN_OR_EXPIRED: return "binding is unknown or expired";
        case PORTILLIA_BINDING_ERR_WRONG_LEASE: return "binding does not belong to the signing lease";
        case PORTILLIA_BINDING_ERR_NEVER_FIXED: return "binding hello was never fixed";
        case PORTILLIA_BINDING_ERR_HELLO_MISMATCH: return "client hello does not match the routed connection";
    }
    return "unknown binding error";
}

/* ------------------------------------------------------------------ */
/* ClientHello accumulator (bindings.go clientHelloAccumulator).      */
/* ------------------------------------------------------------------ */

enum {
    TLS_RECORD_HEADER_LEN = 5,
    TLS_HANDSHAKE_CONTENT_TYPE = 22,
    CLIENT_HELLO_TYPE = 1,
    MAX_TLS_RECORD_PAYLOAD = 1 << 14,
    MAX_CLIENT_HELLO_SIZE = 128 << 10
};

void portillia_ch_accum_init(portillia_ch_accum *acc) {
    memset(acc, 0, sizeof(*acc));
}

void portillia_ch_accum_reset(portillia_ch_accum *acc) {
    free(acc->pending);
    free(acc->hello);
    portillia_ch_accum_init(acc);
}

static bool accum_append(uint8_t **buf, size_t *len, size_t *cap, const uint8_t *data, size_t n) {
    if (*len + n > *cap) {
        size_t new_cap = *cap ? *cap : 4096;
        while (new_cap < *len + n) new_cap *= 2;
        uint8_t *nb = realloc(*buf, new_cap);
        if (!nb) return false;
        *buf = nb;
        *cap = new_cap;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
    return true;
}

portillia_binding_status portillia_ch_accum_add(portillia_ch_accum *acc,
                                                const uint8_t *p, size_t n,
                                                uint8_t **out_hello, size_t *out_hello_len,
                                                bool *out_complete) {
    if (!accum_append(&acc->pending, &acc->pending_len, &acc->pending_cap, p, n)) {
        return PORTILLIA_BINDING_ERR_UNKNOWN;
    }

    while (acc->pending_len >= TLS_RECORD_HEADER_LEN) {
        if (acc->pending[0] != TLS_HANDSHAKE_CONTENT_TYPE) {
            return PORTILLIA_BINDING_ERR_HELLO_MISMATCH; /* non-handshake TLS record */
        }
        size_t record_len = ((size_t)acc->pending[3] << 8) | acc->pending[4];
        if (record_len == 0 || record_len > MAX_TLS_RECORD_PAYLOAD) {
            return PORTILLIA_BINDING_ERR_HELLO_MISMATCH; /* invalid record length */
        }
        if (acc->pending_len < TLS_RECORD_HEADER_LEN + record_len) {
            *out_complete = false;
            return PORTILLIA_BINDING_OK;
        }

        const uint8_t *body = acc->pending + TLS_RECORD_HEADER_LEN;
        size_t body_len = record_len;
        memmove(acc->pending, acc->pending + TLS_RECORD_HEADER_LEN + record_len,
                acc->pending_len - (TLS_RECORD_HEADER_LEN + record_len));
        acc->pending_len -= TLS_RECORD_HEADER_LEN + record_len;

        if (acc->expected == 0 && acc->hello_len < 4) {
            size_t need = 4 - acc->hello_len;
            if (need > body_len) need = body_len;
            if (!accum_append(&acc->hello, &acc->hello_len, &acc->hello_cap, body, need)) {
                return PORTILLIA_BINDING_ERR_UNKNOWN;
            }
            body += need;
            body_len -= need;
            if (acc->hello_len == 4) {
                if (acc->hello[0] != CLIENT_HELLO_TYPE) {
                    return PORTILLIA_BINDING_ERR_HELLO_MISMATCH; /* first message is not a client hello */
                }
                size_t message_len = ((size_t)acc->hello[1] << 16) | ((size_t)acc->hello[2] << 8) | acc->hello[3];
                acc->expected = 4 + message_len;
                if (message_len == 0 || acc->expected > MAX_CLIENT_HELLO_SIZE) {
                    return PORTILLIA_BINDING_ERR_HELLO_MISMATCH; /* invalid handshake length */
                }
            }
        }
        if (acc->expected > 0 && body_len > 0) {
            size_t need = acc->expected - acc->hello_len;
            if (need > body_len) need = body_len;
            if (!accum_append(&acc->hello, &acc->hello_len, &acc->hello_cap, body, need)) {
                return PORTILLIA_BINDING_ERR_UNKNOWN;
            }
            if (acc->hello_len == acc->expected) {
                uint8_t *hello = malloc(acc->hello_len);
                if (!hello) return PORTILLIA_BINDING_ERR_UNKNOWN;
                memcpy(hello, acc->hello, acc->hello_len);
                *out_hello = hello;
                *out_hello_len = acc->hello_len;
                *out_complete = true;
                return PORTILLIA_BINDING_OK;
            }
        }
    }

    if (acc->pending_len > MAX_TLS_RECORD_PAYLOAD + TLS_RECORD_HEADER_LEN) {
        return PORTILLIA_BINDING_ERR_HELLO_MISMATCH; /* record exceeds limit */
    }
    *out_complete = false;
    return PORTILLIA_BINDING_OK;
}
