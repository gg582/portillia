/** @file datagram_client.h
 * @brief QUIC datagram transport client — C port of portal-tunnel/portal/transport/datagram_client.go.
 */
#ifndef PORTILLIA_TRANSPORT_DATAGRAM_CLIENT_H
#define PORTILLIA_TRANSPORT_DATAGRAM_CLIENT_H

#include <portillia/types/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct portillia_datagram_frame_queue {
    portillia_datagram_frame_t *items;
    size_t cap;
    size_t count;
    size_t head;
    size_t tail;
    pthread_mutex_t mu;
    pthread_cond_t cond;
} portillia_datagram_frame_queue_t;

typedef struct portillia_datagram_session {
    void *conn; /* opaque QUIC connection handle */
    pthread_mutex_t mu;
    bool closed;
} portillia_datagram_session_t;

typedef struct portillia_datagram_client {
    portillia_datagram_session_t *session;
    portillia_datagram_frame_queue_t incoming;
    bool closed;
    void (*on_receive_error)(int err);
} portillia_datagram_client_t;

portillia_datagram_client_t *portillia_datagram_client_new(void (*on_receive_error)(int err));
void portillia_datagram_client_destroy(portillia_datagram_client_t *d);

/**
 * @brief Bind a backhaul connection to the datagram client.
 * @return 0 on success, -1 on error.
 */
int portillia_datagram_client_bind(portillia_datagram_client_t *d, void *conn);

/**
 * @brief Accept a datagram frame.
 * @return 0 on success, -1 on error.
 */
int portillia_datagram_client_accept(portillia_datagram_client_t *d, portillia_datagram_frame_t *out, bool *out_cancelled);

/**
 * @brief Send a datagram frame.
 * @return 0 on success, -1 on error.
 */
int portillia_datagram_client_send(portillia_datagram_client_t *d, uint32_t flow_id, const uint8_t *payload, size_t payload_len);

bool portillia_datagram_client_connected(portillia_datagram_client_t *d);
void portillia_datagram_client_clear(portillia_datagram_client_t *d, const char *reason);
void portillia_datagram_client_close(portillia_datagram_client_t *d);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_TRANSPORT_DATAGRAM_CLIENT_H */
