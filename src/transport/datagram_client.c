/** @file datagram_client.c
 * @brief QUIC datagram transport client implementation.
 *
 * Mirrors Go portal/transport/datagram_client.go and datagram_session.go.
 * The queue/encoding layer is fully functional; QUIC backhaul I/O must be
 * wired in by the listener (see listener.c datagram backhaul thread).
 */

#include <portillia/transport/datagram_client.h>
#include <portillia/transport/quic_conn.h>
#include <portillia/utils/log.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define MAX_DATAGRAM_SEGMENTS 256
#define REASSEMBLY_ENTRY_TTL_SEC 5

typedef struct reassembly_segment {
    uint16_t index;
    uint8_t *data;
    size_t len;
    struct reassembly_segment *next;
} reassembly_segment_t;

typedef struct reassembly_entry {
    uint32_t flow_id;
    uint64_t message_id;
    uint16_t segment_count;
    uint16_t received_count;
    size_t total_bytes;
    time_t last_updated;
    reassembly_segment_t *segments;
    struct reassembly_entry *next;
} reassembly_entry_t;

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

static size_t encode_uvarint_64(uint8_t *buf, uint64_t v) {
    size_t i = 0;
    while (v >= 0x80) {
        buf[i++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    buf[i++] = (uint8_t)v;
    return i;
}

static int decode_uvarint_64(const uint8_t *buf, size_t len, uint64_t *out_v, size_t *out_n) {
    uint64_t v = 0;
    size_t shift = 0;
    size_t i = 0;
    while (i < len) {
        uint8_t b = buf[i++];
        v |= (uint64_t)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            *out_v = v;
            *out_n = i;
            return 0;
        }
        shift += 7;
        if (shift > 63) return -1; /* overflow */
    }
    return -1; /* incomplete */
}

static uint8_t *encode_datagram_frame(const portillia_datagram_frame_t *frame, size_t *out_len) {
    uint8_t flow_buf[5];
    size_t flow_n = encode_uvarint(flow_buf, frame->flow_id);

    if (!frame->segmented) {
        size_t total_len = flow_n + 1 + frame->payload_len;
        uint8_t *buf = (uint8_t *)portillia_gc_alloc(total_len);
        if (!buf) return NULL;
        memcpy(buf, flow_buf, flow_n);
        buf[flow_n] = PORTILLIA_DATAGRAM_FLAG_NONE;
        if (frame->payload_len > 0 && frame->payload) {
            memcpy(buf + flow_n + 1, frame->payload, frame->payload_len);
        }
        *out_len = total_len;
        return buf;
    } else {
        uint8_t msg_buf[10];
        uint8_t idx_buf[5];
        uint8_t cnt_buf[5];
        size_t msg_n = encode_uvarint_64(msg_buf, frame->message_id);
        size_t idx_n = encode_uvarint(idx_buf, frame->segment_index);
        size_t cnt_n = encode_uvarint(cnt_buf, frame->segment_count);

        size_t total_len = flow_n + 1 + msg_n + idx_n + cnt_n + frame->payload_len;
        uint8_t *buf = (uint8_t *)portillia_gc_alloc(total_len);
        if (!buf) return NULL;

        size_t pos = 0;
        memcpy(buf + pos, flow_buf, flow_n);
        pos += flow_n;
        buf[pos] = PORTILLIA_DATAGRAM_FLAG_SEGMENTED;
        pos++;
        memcpy(buf + pos, msg_buf, msg_n);
        pos += msg_n;
        memcpy(buf + pos, idx_buf, idx_n);
        pos += idx_n;
        memcpy(buf + pos, cnt_buf, cnt_n);
        pos += cnt_n;
        if (frame->payload_len > 0 && frame->payload) {
            memcpy(buf + pos, frame->payload, frame->payload_len);
        }
        *out_len = total_len;
        return buf;
    }
}

static int decode_datagram(const uint8_t *data, size_t data_len, portillia_datagram_frame_t *out_frame) {
    uint32_t flow_id = 0;
    size_t n = 0;
    if (decode_uvarint(data, data_len, &flow_id, &n) != 0) {
        errno = EBADMSG;
        return -1;
    }
    out_frame->flow_id = flow_id;
    if (n >= data_len) {
        out_frame->payload = NULL;
        out_frame->payload_len = 0;
        out_frame->segmented = false;
        return 0;
    }

    uint8_t flags = data[n];
    if (flags != PORTILLIA_DATAGRAM_FLAG_NONE && flags != PORTILLIA_DATAGRAM_FLAG_SEGMENTED) {
        errno = EBADMSG;
        return -1;
    }

    if (flags == PORTILLIA_DATAGRAM_FLAG_NONE) {
        out_frame->segmented = false;
        size_t payload_len = data_len - (n + 1);
        out_frame->payload_len = payload_len;
        if (payload_len > 0) {
            out_frame->payload = (uint8_t *)portillia_gc_alloc(payload_len);
            if (!out_frame->payload) return -1;
            memcpy(out_frame->payload, data + n + 1, payload_len);
        } else {
            out_frame->payload = NULL;
        }
        return 0;
    }

    /* Segmented case */
    out_frame->segmented = true;
    size_t pos = n + 1;
    uint64_t message_id = 0;
    size_t read_bytes = 0;
    if (decode_uvarint_64(data + pos, data_len - pos, &message_id, &read_bytes) != 0) {
        errno = EBADMSG;
        return -1;
    }
    out_frame->message_id = message_id;
    pos += read_bytes;

    uint32_t segment_index = 0;
    if (decode_uvarint(data + pos, data_len - pos, &segment_index, &read_bytes) != 0) {
        errno = EBADMSG;
        return -1;
    }
    out_frame->segment_index = (uint16_t)segment_index;
    pos += read_bytes;

    uint32_t segment_count = 0;
    if (decode_uvarint(data + pos, data_len - pos, &segment_count, &read_bytes) != 0) {
        errno = EBADMSG;
        return -1;
    }
    out_frame->segment_count = (uint16_t)segment_count;
    pos += read_bytes;

    size_t payload_len = data_len - pos;
    out_frame->payload_len = payload_len;
    if (payload_len > 0) {
        out_frame->payload = (uint8_t *)portillia_gc_alloc(payload_len);
        if (!out_frame->payload) return -1;
        memcpy(out_frame->payload, data + pos, payload_len);
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

static void free_reassembly_entry(reassembly_entry_t *entry) {
    if (!entry) return;
    reassembly_segment_t *seg = entry->segments;
    while (seg) {
        reassembly_segment_t *next = seg->next;
        if (seg->data) portillia_gc_free_later(seg->data);
        portillia_gc_free_later(seg);
        seg = next;
    }
    portillia_gc_free_later(entry);
}

static void free_reassembly_list(reassembly_entry_t *head) {
    reassembly_entry_t *curr = head;
    while (curr) {
        reassembly_entry_t *next = curr->next;
        free_reassembly_entry(curr);
        curr = next;
    }
}

static void clean_expired_reassemblies(portillia_datagram_client_t *d) {
    time_t now = time(NULL);
    reassembly_entry_t **pp = (reassembly_entry_t **)&d->reassembly_head;
    while (*pp) {
        reassembly_entry_t *entry = *pp;
        if (now - entry->last_updated > REASSEMBLY_ENTRY_TTL_SEC) {
            *pp = entry->next;
            free_reassembly_entry(entry);
        } else {
            pp = &entry->next;
        }
    }
}

/* ---------- Public API ---------- */

portillia_datagram_client_t *portillia_datagram_client_new(void (*on_receive_error)(int err)) {
    portillia_datagram_client_t *d = PORTILLIA_GC_NEW_ZERO(portillia_datagram_client_t);
    frame_queue_init(&d->incoming);
    d->on_receive_error = on_receive_error;
    d->next_message_id = 0;
    d->reassembly_head = NULL;
    pthread_mutex_init(&d->reassembly_mu, NULL);
    return d;
}

void portillia_datagram_client_destroy(portillia_datagram_client_t *d) {
    if (!d) return;
    portillia_datagram_client_close(d);
    frame_queue_free(&d->incoming);
    pthread_mutex_lock(&d->reassembly_mu);
    free_reassembly_list((reassembly_entry_t *)d->reassembly_head);
    d->reassembly_head = NULL;
    pthread_mutex_unlock(&d->reassembly_mu);
    pthread_mutex_destroy(&d->reassembly_mu);
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

    if (frame.segmented) {
        if (frame.segment_count == 0 || frame.segment_index >= frame.segment_count || frame.segment_count > MAX_DATAGRAM_SEGMENTS) {
            portillia_datagram_frame_cleanup(&frame);
            return;
        }

        pthread_mutex_lock(&d->reassembly_mu);
        clean_expired_reassemblies(d);

        reassembly_entry_t *entry = (reassembly_entry_t *)d->reassembly_head;
        while (entry) {
            if (entry->flow_id == frame.flow_id && entry->message_id == frame.message_id) {
                break;
            }
            entry = entry->next;
        }

        if (!entry) {
            entry = PORTILLIA_GC_NEW_ZERO(reassembly_entry_t);
            if (!entry) {
                pthread_mutex_unlock(&d->reassembly_mu);
                portillia_datagram_frame_cleanup(&frame);
                return;
            }
            entry->flow_id = frame.flow_id;
            entry->message_id = frame.message_id;
            entry->segment_count = frame.segment_count;
            entry->last_updated = time(NULL);
            entry->next = (reassembly_entry_t *)d->reassembly_head;
            d->reassembly_head = entry;
        }

        if (entry->segment_count != frame.segment_count) {
            pthread_mutex_unlock(&d->reassembly_mu);
            portillia_datagram_frame_cleanup(&frame);
            return;
        }

        reassembly_segment_t *seg = entry->segments;
        bool exists = false;
        while (seg) {
            if (seg->index == frame.segment_index) {
                exists = true;
                break;
            }
            seg = seg->next;
        }

        if (!exists) {
            reassembly_segment_t *new_seg = PORTILLIA_GC_NEW_ZERO(reassembly_segment_t);
            if (new_seg) {
                new_seg->index = frame.segment_index;
                new_seg->len = frame.payload_len;
                if (frame.payload_len > 0) {
                    new_seg->data = (uint8_t *)portillia_gc_alloc(frame.payload_len);
                    if (new_seg->data) {
                        memcpy(new_seg->data, frame.payload, frame.payload_len);
                    }
                }
                new_seg->next = entry->segments;
                entry->segments = new_seg;
                entry->received_count++;
                entry->total_bytes += frame.payload_len;
            }
        }
        entry->last_updated = time(NULL);

        if (entry->received_count == entry->segment_count) {
            uint8_t *merged = (uint8_t *)portillia_gc_alloc(entry->total_bytes);
            if (merged) {
                size_t pos = 0;
                bool complete = true;
                for (uint16_t i = 0; i < entry->segment_count; i++) {
                    reassembly_segment_t *s = entry->segments;
                    while (s) {
                        if (s->index == i) break;
                        s = s->next;
                    }
                    if (!s) {
                        complete = false;
                        break;
                    }
                    if (s->len > 0 && s->data) {
                        memcpy(merged + pos, s->data, s->len);
                        pos += s->len;
                    }
                }

                if (complete) {
                    portillia_datagram_frame_t complete_frame = {0};
                    complete_frame.flow_id = frame.flow_id;
                    complete_frame.payload = merged;
                    complete_frame.payload_len = entry->total_bytes;
                    complete_frame.segmented = false;
                    frame_queue_push(&d->incoming, &complete_frame, true);
                    portillia_datagram_frame_cleanup(&complete_frame);
                } else {
                    portillia_gc_free_later(merged);
                }
            }

            /* remove from list */
            reassembly_entry_t **pp = (reassembly_entry_t **)&d->reassembly_head;
            while (*pp) {
                if (*pp == entry) {
                    *pp = entry->next;
                    break;
                }
                pp = &(*pp)->next;
            }
            free_reassembly_entry(entry);
        }

        pthread_mutex_unlock(&d->reassembly_mu);
        portillia_datagram_frame_cleanup(&frame);
    } else {
        frame_queue_push(&d->incoming, &frame, true);
        portillia_datagram_frame_cleanup(&frame);
    }
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

    if (payload_len <= PORTILLIA_DEFAULT_DATAGRAM_SEGMENT_PAYLOAD) {
        portillia_datagram_frame_t frame = {0};
        frame.flow_id = flow_id;
        frame.payload = (uint8_t *)payload;
        frame.payload_len = payload_len;
        frame.segmented = false;

        size_t encoded_len = 0;
        uint8_t *encoded = encode_datagram_frame(&frame, &encoded_len);
        if (!encoded) { errno = ENOMEM; return -1; }

        int rv = portillia_quic_conn_send_datagram((portillia_quic_conn_t *)d->session->conn, encoded, encoded_len);
        portillia_gc_free_later(encoded);
        if (rv != 0) { errno = EIO; return -1; }
        return 0;
    }

    /* Segmented send */
    pthread_mutex_lock(&d->session->mu);
    d->next_message_id++;
    uint64_t msg_id = d->next_message_id;
    pthread_mutex_unlock(&d->session->mu);

    size_t segment_count = (payload_len + PORTILLIA_DEFAULT_DATAGRAM_SEGMENT_PAYLOAD - 1) / PORTILLIA_DEFAULT_DATAGRAM_SEGMENT_PAYLOAD;
    if (segment_count > MAX_DATAGRAM_SEGMENTS) {
        errno = EMSGSIZE;
        return -1;
    }

    for (size_t i = 0; i < segment_count; i++) {
        size_t start = i * PORTILLIA_DEFAULT_DATAGRAM_SEGMENT_PAYLOAD;
        size_t end = start + PORTILLIA_DEFAULT_DATAGRAM_SEGMENT_PAYLOAD;
        if (end > payload_len) {
            end = payload_len;
        }

        portillia_datagram_frame_t frame = {0};
        frame.flow_id = flow_id;
        frame.payload = (uint8_t *)(payload + start);
        frame.payload_len = end - start;
        frame.segmented = true;
        frame.message_id = msg_id;
        frame.segment_index = (uint16_t)i;
        frame.segment_count = (uint16_t)segment_count;

        size_t encoded_len = 0;
        uint8_t *encoded = encode_datagram_frame(&frame, &encoded_len);
        if (!encoded) { errno = ENOMEM; return -1; }

        int rv = portillia_quic_conn_send_datagram((portillia_quic_conn_t *)d->session->conn, encoded, encoded_len);
        portillia_gc_free_later(encoded);
        if (rv != 0) { errno = EIO; return -1; }
    }

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
    pthread_mutex_lock(&d->reassembly_mu);
    free_reassembly_list((reassembly_entry_t *)d->reassembly_head);
    d->reassembly_head = NULL;
    pthread_mutex_unlock(&d->reassembly_mu);
}

void portillia_datagram_client_close(portillia_datagram_client_t *d) {
    if (!d) return;
    d->closed = true;
    frame_queue_close(&d->incoming);
    pthread_mutex_lock(&d->reassembly_mu);
    free_reassembly_list((reassembly_entry_t *)d->reassembly_head);
    d->reassembly_head = NULL;
    pthread_mutex_unlock(&d->reassembly_mu);
    if (d->session) {
        pthread_mutex_lock(&d->session->mu);
        d->session->closed = true;
        pthread_mutex_unlock(&d->session->mu);
    }
}
