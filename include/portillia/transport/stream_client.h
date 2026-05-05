/** @file stream_client.h
 * @brief Reverse stream transport client — C port of portal-tunnel/portal/transport/stream_client.go.
 */
#ifndef PORTILLIA_TRANSPORT_STREAM_CLIENT_H
#define PORTILLIA_TRANSPORT_STREAM_CLIENT_H

#include <portillia/types/types.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct portillia_stream_client {
    portillia_net_conn_t **accepted_conns; /* Array of accepted connection handles */
    size_t accepted_count;
    size_t accepted_cap;
    size_t accepted_head;  /* Read index */
    size_t accepted_tail;  /* Write index */
    pthread_mutex_t mu;
    pthread_cond_t cond;
    int handshake_timeout_sec;
    bool closed;
} portillia_stream_client_t;

portillia_stream_client_t *portillia_stream_client_new(int ready_target, int handshake_timeout_sec);
void portillia_stream_client_destroy(portillia_stream_client_t *s);

/**
 * @brief Accept a connection from the stream.
 * @return Connection handle on success, NULL on error (errno = EBADF if closed).
 */
portillia_net_conn_t *portillia_stream_client_accept(portillia_stream_client_t *s, bool *out_cancelled);

/**
 * @brief Run a reverse session on the given connection.
 * Reads markers and dispatches to TLS or raw activation.
 * @param conn_fd    Connected socket fd.
 * @param outer_ssl  Existing outer SSL session (NULL for plain TCP).
 * @param inner_ctx  Server-side SSL context for inner TLS handshake (NULL if TLS unsupported).
 * @return claimed true if a session was claimed, false on keepalive/close.
 */
bool portillia_stream_client_run_session(portillia_stream_client_t *s, int conn_fd, SSL *outer_ssl, SSL_CTX *inner_ctx, int *out_err);

/**
 * @brief Drain all pending accepted connections.
 */
void portillia_stream_client_drain(portillia_stream_client_t *s);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_TRANSPORT_STREAM_CLIENT_H */
