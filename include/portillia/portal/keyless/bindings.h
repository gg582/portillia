#ifndef PORTILLIA_PORTAL_KEYLESS_BINDINGS_H
#define PORTILLIA_PORTAL_KEYLESS_BINDINGS_H

/*
 * C port of portal-tunnel portal/keyless/bindings.go.
 *
 * A BindingRegistry owns the relay's connection-binding policy for keyless
 * transcript signing. The relay mints a 16-byte binding per claimed reverse
 * session, pins it to the sha256 of the first relay-observed ClientHello, and
 * spends it (single use) on a /v1/sign request that presents the same
 * ClientHello transcript and lease.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PORTILLIA_BINDING_SIZE 16
#define PORTILLIA_BINDING_HELLO_HASH_SIZE 32

/* Error codes mirroring the Go error strings in bindings.go. */
typedef enum {
    PORTILLIA_BINDING_OK = 0,
    PORTILLIA_BINDING_ERR_HELLO_REQUIRED,   /* "client hello span is required" / "client hello transcript is required" */
    PORTILLIA_BINDING_ERR_UNKNOWN,          /* "binding is unknown" */
    PORTILLIA_BINDING_ERR_EXPIRED,          /* "binding is expired" */
    PORTILLIA_BINDING_ERR_ALREADY_FIXED,    /* "binding hello is already fixed" */
    PORTILLIA_BINDING_ERR_BAD_SIZE,         /* "binding must be 16 bytes" */
    PORTILLIA_BINDING_ERR_UNKNOWN_OR_EXPIRED, /* "binding is unknown or expired" */
    PORTILLIA_BINDING_ERR_WRONG_LEASE,      /* "binding does not belong to the signing lease" */
    PORTILLIA_BINDING_ERR_NEVER_FIXED,      /* "binding hello was never fixed" */
    PORTILLIA_BINDING_ERR_HELLO_MISMATCH    /* "client hello does not match the routed connection" */
} portillia_binding_status;

typedef struct portillia_binding_registry portillia_binding_registry;

/* Creates a registry whose issued bindings live ttl seconds. */
portillia_binding_registry *portillia_bindings_new(uint64_t ttl_seconds);
void portillia_bindings_free(portillia_binding_registry *reg);

/* Returns the process-wide registry used by the relay (lazy init, ttl 300s). */
portillia_binding_registry *portillia_bindings_shared(void);

/*
 * Issue mints a binding. A NULL/zero-length clientHello leaves the entry
 * unfixed until portillia_bindings_fix_hello. Fills out_binding (16 bytes).
 */
void portillia_bindings_issue(portillia_binding_registry *reg,
                              const char *lease_id,
                              const uint8_t *client_hello, size_t client_hello_len,
                              uint8_t out_binding[PORTILLIA_BINDING_SIZE]);

/* FixHello pins a ClientHello to a binding issued without one. */
portillia_binding_status portillia_bindings_fix_hello(portillia_binding_registry *reg,
                                                      const uint8_t binding[PORTILLIA_BINDING_SIZE],
                                                      const uint8_t *client_hello, size_t client_hello_len);

/*
 * ValidateAndConsume validates the lease and ClientHello and spends the
 * binding: on success the entry is deleted (single use).
 */
portillia_binding_status portillia_bindings_validate_and_consume(portillia_binding_registry *reg,
                                                                 const uint8_t *binding, size_t binding_len,
                                                                 const char *lease_id,
                                                                 const uint8_t *client_hello, size_t client_hello_len);

/* Discard revokes a binding that was not delivered to a live stream. */
void portillia_bindings_discard(portillia_binding_registry *reg,
                                const uint8_t binding[PORTILLIA_BINDING_SIZE]);

/* SweepExpired reclaims expired, unused bindings. */
void portillia_bindings_sweep_expired(portillia_binding_registry *reg, struct timespec now);

const char *portillia_binding_strerror(portillia_binding_status status);

/* ------------------------------------------------------------------ */
/* ClientHello accumulator (bindings.go clientHelloAccumulator).      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *pending;
    size_t pending_len;
    size_t pending_cap;
    uint8_t *hello;
    size_t hello_len;
    size_t hello_cap;
    size_t expected; /* 0 until the 4-byte handshake header is complete */
} portillia_ch_accum;

void portillia_ch_accum_init(portillia_ch_accum *acc);
void portillia_ch_accum_reset(portillia_ch_accum *acc);

/*
 * Feeds bytes into the accumulator. Returns PORTILLIA_BINDING_OK with
 * *out_complete=true and *out_hello (malloc'ed, caller frees) once the first
 * ClientHello handshake message is fully assembled. Non-handshake records,
 * invalid record lengths, a non-ClientHello first message, and messages over
 * 128 KiB fail with PORTILLIA_BINDING_ERR_* codes; *out_complete stays false
 * while more data is needed.
 */
portillia_binding_status portillia_ch_accum_add(portillia_ch_accum *acc,
                                                const uint8_t *p, size_t n,
                                                uint8_t **out_hello, size_t *out_hello_len,
                                                bool *out_complete);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_PORTAL_KEYLESS_BINDINGS_H */
