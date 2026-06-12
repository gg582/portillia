/** @file datagram_client.c
 * @brief QUIC datagram transport client implementation.
 *
 * Mirrors Go portal/transport/datagram_client.go and datagram_session.go.
 * Simplified datagram encoding: [flowID varint][payload bytes] without segmentation.
 */

#include <portillia/transport/datagram_client.h>
#include <portillia/transport/quic_conn.h>
#include <portillia/utils/log.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static size_t encode_uvarint(uint8_t *buf, uint32_t v) {
    size_t i = 0;
    while (v >= 0x80) {
        buf[i++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    buf[i++] = (uint8_t)v;
    return i;
}

static int decode_uvarint(const uint8_t *buf, size_t len, uint32_t *out_v, size_t *out_n) {
    uint32_t v = 0;
    size_t shift = 0;
    size_t i = 0;
    while (i < len) {
        uint8_t b = buf[i++];
        v |= (uint32_t)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            *out_v = v;
            *out_n = i;
            return 0;
        }
        shift += 7;
        if (shift > 28) return -1; /* overflow */
    }
    return -1; /* incomplete */
}

static uint8_t *encode_datagram_frame(const portillia_datagram_frame_t *frame, size_t *out_len) {
    uint8_t flow_buf[5];
    size_t flow_n = encode_uvarint(flow_buf, frame->flow_id);

    size_t total_len = flow_n + frame->payload_len;
    uint8_t *buf = (uint8_t *)portillia_gc_alloc(total_len);
    if (!buf) return NULL;
    memcpy(buf, flow_buf, flow_n);
    if (frame->payload_len > 0 && frame->payload) {
        memcpy(buf + flow_n, frame->payload, frame->payload_len);
    }
    *out_len = total_len;
    return buf;
}

static int decode_datagram(const uint8_t *data, size_t data_len, portillia_datagram_frame_t *out_frame) {
    uint32_t flow_id = 0;
    size_t n = 0;
    if (decode_uvarint(data, data_len, &flow_id, &n) != 0) {
        errno = EBADMSG;
        return -1;
    }
    out_frame->flow_id = flow_id;
    size_t payload_len = data_len - n;
    out_frame->payload_len = payload_len;
    if (payload_len > 0) {
        out_frame->payload = (uint8_t *)portillia_gc_alloc(payload_len);
        if (!out_frame->payload) return -1;
        memcpy(out_frame->payload, data + n, payload_len);
    } else {
        out_frame->payload = NULL;
    }
    return 0;
}

/* ---------- Queue helpers ---------- */

#define DATAGRAM_QUEUE_CAP 256

static void frame_queue_init(portillia_datagram_frame_queue_t *q) {
    memset(q, 0, sizeof(*q));
    q->cap = DATAGRAM_QUEUE_CAP;
    q->items = (portillia_datagram_frame_t *)portillia_gc_alloc(sizeof(portillia_datagram_frame_t) * q->cap);
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void frame_queue_close(portillia_datagram_frame_queue_t *q) {
    if (!q) return;
    pthread_mutex_lock(&q->mu);
    q->count = 0;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mu);
}

static void frame_queue_free(portillia_datagram_frame_queue_t *q) {
    if (!q) return;
    pthread_mutex_lock(&q->mu);
    for (size_t i = 0; i < q->count; i++) {
        size_t idx = (q->head + i) % q->cap;
        portillia_datagram_frame_cleanup(&q->items[idx]);
    }
    q->count = 0;
    pthread_mutex_unlock(&q->mu);
    pthread_mutex_destroy(&q->mu);
    pthread_cond_destroy(&q->cond);
}

static bool frame_queue_push(portillia_datagram_frame_queue_t *q, const portillia_datagram_frame_t *frame, bool drop_if_full) {
    if (!q || !frame) return false;
    pthread_mutex_lock(&q->mu);
    if (q->count >= q->cap) {
        if (drop_if_full) {
            /* drop oldest */
            portillia_datagram_frame_cleanup(&q->items[q->head]);
            q->head = (q->head + 1) % q->cap;
            q->count--;
        } else {
            pthread_mutex_unlock(&q->mu);
            return false;
        }
    }
    size_t idx = (q->head + q->count) % q->cap;
    portillia_datagram_frame_copy(&q->items[idx], frame);
    q->count++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mu);
    return true;
}

static bool frame_queue_pop(portillia_datagram_frame_queue_t *q, portillia_datagram_frame_t *out, bool *out_cancelled) {
    if (!q || !out) return false;
    pthread_mutex_lock(&q->mu);
    while (q->count == 0) {
        if (out_cancelled && *out_cancelled) {
            pthread_mutex_unlock(&q->mu);
            return false;
        }
        pthread_cond_wait(&q->cond, &q->mu);
    }
    size_t idx = q->head;
    portillia_datagram_frame_copy(out, &q->items[idx]);
    portillia_datagram_frame_cleanup(&q->items[idx]);
    q->head = (q->head + 1) % q->cap;
    q->count--;
    pthread_mutex_unlock(&q->mu);
    return true;
}

/* ---------- Public API ---------- */

portillia_datagram_client_t *portillia_datagram_client_new(void (*on_receive_error)(int err)) {
    portillia_datagram_client_t *d = PORTILLIA_GC_NEW_ZERO(portillia_datagram_client_t);
    frame_queue_init(&d->incoming);
    d->on_receive_error = on_receive_error;
    return d;
}

void portillia_datagram_client_destroy(portillia_datagram_client_t *d) {
    if (!d) return;
    portillia_datagram_client_close(d);
    frame_queue_free(&d->incoming);
    if (d->session) {
        portillia_gc_free_later(d->session);
    }
    portillia_gc_free_later(d);
}

static void quic_recv_handler(void *user_data, const uint8_t *data, size_t len) {
    portillia_datagram_client_t *d = (portillia_datagram_client_t *)user_data;
    if (!d || d->closed) return;

    portillia_datagram_frame_t frame = {0};
    if (decode_datagram(data, len, &frame) != 0) return;

    frame_queue_push(&d->incoming, &frame, true);
    portillia_datagram_frame_cleanup(&frame);
}

int portillia_datagram_client_bind(portillia_datagram_client_t *d, void *conn) {
    if (!d) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&d->session->mu);
    d->session->conn = conn;
    pthread_mutex_unlock(&d->session->mu);
    if (conn) {
        portillia_quic_conn_set_recv_handler((portillia_quic_conn_t *)conn, quic_recv_handler, d);
    }
    return 0;
}

int portillia_datagram_client_accept(portillia_datagram_client_t *d, portillia_datagram_frame_t *out, bool *out_cancelled) {
    if (!d || d->closed) { errno = EBADF; return -1; }
    if (!out) { errno = EINVAL; return -1; }
    if (frame_queue_pop(&d->incoming, out, out_cancelled)) {
        return 0;
    }
    if (out_cancelled && *out_cancelled) {
        errno = ECANCELED;
        return -1;
    }
    errno = EIO;
    return -1;
}

int portillia_datagram_client_send(portillia_datagram_client_t *d, uint32_t flow_id, const uint8_t *payload, size_t payload_len) {
    if (!d || d->closed) { errno = EBADF; return -1; }
    if (!payload && payload_len > 0) { errno = EINVAL; return -1; }

    if (!d->session || !d->session->conn) {
        return 0;
    }

    portillia_datagram_frame_t frame = {0};
    frame.flow_id = flow_id;
    frame.payload = (uint8_t *)payload;
    frame.payload_len = payload_len;

    size_t encoded_len = 0;
    uint8_t *encoded = encode_datagram_frame(&frame, &encoded_len);
    if (!encoded) { errno = ENOMEM; return -1; }

    int rv = portillia_quic_conn_send_datagram((portillia_quic_conn_t *)d->session->conn, encoded, encoded_len);
    portillia_gc_free_later(encoded);
    if (rv != 0) { errno = EIO; return -1; }
    return 0;
}

bool portillia_datagram_client_connected(portillia_datagram_client_t *d) {
    if (!d || d->closed) return false;
    if (!d->session) return false;
    pthread_mutex_lock(&d->session->mu);
    bool has_conn = d->session->conn != NULL;
    pthread_mutex_unlock(&d->session->mu);
    return has_conn;
}

void portillia_datagram_client_clear(portillia_datagram_client_t *d, const char *reason) {
    (void)reason;
    if (!d) return;
    if (d->session) {
        pthread_mutex_lock(&d->session->mu);
        d->session->conn = NULL;
        pthread_mutex_unlock(&d->session->mu);
    }
    frame_queue_close(&d->incoming);
}

void portillia_datagram_client_close(portillia_datagram_client_t *d) {
    if (!d) return;
    d->closed = true;
    frame_queue_close(&d->incoming);
    if (d->session) {
        pthread_mutex_lock(&d->session->mu);
        d->session->closed = true;
        pthread_mutex_unlock(&d->session->mu);
    }
}
