/** @file quic_conn.h
 * @brief Minimal ngtcp2-based QUIC datagram connection.
 */
#ifndef PORTILLIA_TRANSPORT_QUIC_CONN_H
#define PORTILLIA_TRANSPORT_QUIC_CONN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct portillia_quic_conn portillia_quic_conn_t;

/**
 * @brief Create a QUIC connection to the given host/port.
 * @return Connection handle, or NULL on error.
 */
portillia_quic_conn_t *portillia_quic_conn_new(const char *host, int port);

/**
 * @brief Free a QUIC connection and stop its I/O thread.
 */
void portillia_quic_conn_free(portillia_quic_conn_t *qc);

/**
 * @brief Send a datagram over the QUIC connection.
 * @return 0 on success, -1 on error.
 */
int portillia_quic_conn_send_datagram(portillia_quic_conn_t *qc, const uint8_t *data, size_t len);

/**
 * @brief Set the callback for received datagrams.
 */
void portillia_quic_conn_set_recv_handler(portillia_quic_conn_t *qc,
    void (*cb)(void *user_data, const uint8_t *data, size_t len), void *user_data);

/**
 * @brief Check if the QUIC handshake is complete.
 */
bool portillia_quic_conn_handshake_done(portillia_quic_conn_t *qc);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_TRANSPORT_QUIC_CONN_H */
