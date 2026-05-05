/** @file stream_client.c
 * @brief Reverse stream transport client implementation.
 */

#include <portillia/transport/stream_client.h>
#include <portillia/utils/log.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

/* ---------- Ring buffer helpers ---------- */

static bool ring_push(portillia_stream_client_t *s, portillia_net_conn_t *conn) {
    pthread_mutex_lock(&s->mu);
    if (s->closed) { pthread_mutex_unlock(&s->mu); return false; }
    if (s->accepted_count >= s->accepted_cap) {
        pthread_mutex_unlock(&s->mu);
        return false;
    }
    s->accepted_conns[s->accepted_tail] = conn;
    s->accepted_tail = (s->accepted_tail + 1) % s->accepted_cap;
    s->accepted_count++;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->mu);
    return true;
}

static portillia_net_conn_t *ring_pop(portillia_stream_client_t *s, bool *out_cancelled) {
    pthread_mutex_lock(&s->mu);
    while (s->accepted_count == 0 && !s->closed) {
        pthread_cond_wait(&s->cond, &s->mu);
    }
    if (s->closed) {
        pthread_mutex_unlock(&s->mu);
        if (out_cancelled) *out_cancelled = true;
        errno = EBADF;
        return NULL;
    }
    portillia_net_conn_t *conn = s->accepted_conns[s->accepted_head];
    s->accepted_head = (s->accepted_head + 1) % s->accepted_cap;
    s->accepted_count--;
    pthread_mutex_unlock(&s->mu);
    if (out_cancelled) *out_cancelled = false;
    return conn;
}

/* ---------- Lifecycle ---------- */

portillia_stream_client_t *portillia_stream_client_new(int ready_target, int handshake_timeout_sec) {
    size_t cap = (size_t)(ready_target > 0 ? ready_target * 2 : 2);
    portillia_stream_client_t *s = PORTILLIA_GC_NEW_ZERO(portillia_stream_client_t);
    if (!s) return NULL;
    s->accepted_conns = (portillia_net_conn_t **)portillia_gc_alloc(sizeof(portillia_net_conn_t *) * cap);
    if (!s->accepted_conns) { portillia_gc_free_later(s); return NULL; }
    s->accepted_cap = cap;
    s->handshake_timeout_sec = handshake_timeout_sec;
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cond, NULL);
    return s;
}

void portillia_stream_client_destroy(portillia_stream_client_t *s) {
    if (!s) return;
    portillia_stream_client_drain(s);
    pthread_mutex_lock(&s->mu);
    s->closed = true;
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->mu);
    pthread_mutex_destroy(&s->mu);
    pthread_cond_destroy(&s->cond);
    if (s->accepted_conns) portillia_gc_free_later(s->accepted_conns);
    portillia_gc_free_later(s);
}

/* ---------- Public API ---------- */

portillia_net_conn_t *portillia_stream_client_accept(portillia_stream_client_t *s, bool *out_cancelled) {
    if (!s) { errno = EINVAL; return NULL; }
    return ring_pop(s, out_cancelled);
}

static ssize_t session_read(int fd, SSL *outer_ssl, void *buf, size_t len) {
    if (outer_ssl) {
        return (ssize_t)SSL_read(outer_ssl, buf, (int)len);
    }
    return read(fd, buf, len);
}

static bool perform_tls_handshake(portillia_stream_client_t *s, int conn_fd, SSL *outer_ssl, SSL_CTX *inner_ctx, portillia_net_conn_t **out_conn) {
    if (!inner_ctx) {
        LOG_WARN("Transport: TLS marker received but no inner TLS context available");
        return false;
    }
    SSL *ssl = SSL_new(inner_ctx);
    if (!ssl) {
        LOG_WARN("Transport: SSL_new failed for inner TLS");
        return false;
    }
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio) {
        if (rbio) BIO_free(rbio);
        if (wbio) BIO_free(wbio);
        SSL_free(ssl);
        return false;
    }
    SSL_set_bio(ssl, rbio, wbio);

    int saved_timeout = s->handshake_timeout_sec;
    time_t deadline = time(NULL) + (saved_timeout > 0 ? saved_timeout : 15);

    while (1) {
        int rc = SSL_accept(ssl);
        if (rc == 1) break;
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ) {
            char buf[4096];
            int n = SSL_read(outer_ssl, buf, sizeof(buf));
            if (n <= 0) {
                int outer_err = SSL_get_error(outer_ssl, n);
                if (outer_err == SSL_ERROR_WANT_READ || outer_err == SSL_ERROR_WANT_WRITE) {
                    if (time(NULL) >= deadline) {
                        LOG_WARN("Transport: inner TLS handshake timed out");
                        SSL_free(ssl);
                        return false;
                    }
                    usleep(10000);
                    continue;
                }
                LOG_WARN("Transport: outer SSL read failed during inner handshake (err=%d)", outer_err);
                SSL_free(ssl);
                return false;
            }
            BIO_write(rbio, buf, n);
        } else if (err == SSL_ERROR_WANT_WRITE) {
            char buf[4096];
            int n = BIO_read(wbio, buf, sizeof(buf));
            if (n > 0) {
                int w = 0;
                while (w < n) {
                    int wr = SSL_write(outer_ssl, buf + w, n - w);
                    if (wr <= 0) {
                        int outer_err = SSL_get_error(outer_ssl, wr);
                        if (outer_err == SSL_ERROR_WANT_READ || outer_err == SSL_ERROR_WANT_WRITE) {
                            if (time(NULL) >= deadline) {
                                LOG_WARN("Transport: inner TLS handshake timed out");
                                SSL_free(ssl);
                                return false;
                            }
                            usleep(10000);
                            continue;
                        }
                        LOG_WARN("Transport: outer SSL write failed during inner handshake (err=%d)", outer_err);
                        SSL_free(ssl);
                        return false;
                    }
                    w += wr;
                }
            }
        } else {
            LOG_WARN("Transport: inner TLS handshake failed (err=%d)", err);
            SSL_free(ssl);
            return false;
        }
        if (time(NULL) >= deadline) {
            LOG_WARN("Transport: inner TLS handshake timed out");
            SSL_free(ssl);
            return false;
        }
    }

    portillia_net_conn_t *conn = PORTILLIA_GC_NEW_ZERO(portillia_net_conn_t);
    if (!conn) {
        SSL_free(ssl);
        return false;
    }
    conn->fd = conn_fd;
    conn->ssl = ssl;
    conn->outer_ssl = outer_ssl;
    conn->owns_ssl = true;
    conn->closed = false;

    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    if (getsockname(conn_fd, (struct sockaddr *)&ss, &ss_len) == 0) {
        strncpy(conn->local.network, "tcp", sizeof(conn->local.network) - 1);
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
            inet_ntop(AF_INET, &sin->sin_addr, conn->local.address, sizeof(conn->local.address));
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            inet_ntop(AF_INET6, &sin6->sin6_addr, conn->local.address, sizeof(conn->local.address));
        }
    }
    ss_len = sizeof(ss);
    if (getpeername(conn_fd, (struct sockaddr *)&ss, &ss_len) == 0) {
        strncpy(conn->remote.network, "tcp", sizeof(conn->remote.network) - 1);
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
            inet_ntop(AF_INET, &sin->sin_addr, conn->remote.address, sizeof(conn->remote.address));
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            inet_ntop(AF_INET6, &sin6->sin6_addr, conn->remote.address, sizeof(conn->remote.address));
        }
    }

    *out_conn = conn;
    return true;
}

bool portillia_stream_client_run_session(portillia_stream_client_t *s, int conn_fd, SSL *outer_ssl, SSL_CTX *inner_ctx, int *out_err) {
    if (!s) { if (out_err) *out_err = EBADF; return false; }
    if (conn_fd < 0) { if (out_err) *out_err = EBADF; return false; }

    uint8_t marker;
    while (1) {
        ssize_t nr = session_read(conn_fd, outer_ssl, &marker, 1);
        if (nr <= 0) {
            if (outer_ssl) {
                SSL_shutdown(outer_ssl);
                SSL_free(outer_ssl);
            }
            close(conn_fd);
            if (out_err) *out_err = EPIPE;
            return false;
        }

        switch (marker) {
            case PORTILLIA_MARKER_KEEPALIVE:
                continue;
            case PORTILLIA_MARKER_TLS_START: {
                portillia_net_conn_t *conn = NULL;
                if (!perform_tls_handshake(s, conn_fd, outer_ssl, inner_ctx, &conn)) {
                    if (outer_ssl) {
                        SSL_shutdown(outer_ssl);
                        SSL_free(outer_ssl);
                    }
                    close(conn_fd);
                    if (out_err) *out_err = EPROTO;
                    return false;
                }
                /* conn now owns both inner ssl and outer_ssl */
                if (!ring_push(s, conn)) {
                    portillia_net_conn_cleanup(conn);
                    portillia_gc_free_later(conn);
                }
                if (out_err) *out_err = 0;
                return true;
            }
            case PORTILLIA_MARKER_RAW_START: {
                portillia_net_conn_t *conn = PORTILLIA_GC_NEW_ZERO(portillia_net_conn_t);
                if (!conn) {
                    if (outer_ssl) {
                        SSL_shutdown(outer_ssl);
                        SSL_free(outer_ssl);
                    }
                    close(conn_fd);
                    if (out_err) *out_err = ENOMEM;
                    return false;
                }
                conn->fd = conn_fd;
                conn->outer_ssl = outer_ssl;
                conn->owns_ssl = (outer_ssl != NULL);
                conn->closed = false;

                struct sockaddr_storage ss;
                socklen_t ss_len = sizeof(ss);
                if (getsockname(conn_fd, (struct sockaddr *)&ss, &ss_len) == 0) {
                    strncpy(conn->local.network, "tcp", sizeof(conn->local.network) - 1);
                    if (ss.ss_family == AF_INET) {
                        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
                        inet_ntop(AF_INET, &sin->sin_addr, conn->local.address, sizeof(conn->local.address));
                    } else if (ss.ss_family == AF_INET6) {
                        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
                        inet_ntop(AF_INET6, &sin6->sin6_addr, conn->local.address, sizeof(conn->local.address));
                    }
                }
                ss_len = sizeof(ss);
                if (getpeername(conn_fd, (struct sockaddr *)&ss, &ss_len) == 0) {
                    strncpy(conn->remote.network, "tcp", sizeof(conn->remote.network) - 1);
                    if (ss.ss_family == AF_INET) {
                        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
                        inet_ntop(AF_INET, &sin->sin_addr, conn->remote.address, sizeof(conn->remote.address));
                    } else if (ss.ss_family == AF_INET6) {
                        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
                        inet_ntop(AF_INET6, &sin6->sin6_addr, conn->remote.address, sizeof(conn->remote.address));
                    }
                }

                if (!ring_push(s, conn)) {
                    portillia_net_conn_cleanup(conn);
                    portillia_gc_free_later(conn);
                }
                if (out_err) *out_err = 0;
                return true;
            }
            default:
                LOG_WARN("Transport: unexpected reverse marker 0x%02x", marker);
                if (outer_ssl) {
                    SSL_shutdown(outer_ssl);
                    SSL_free(outer_ssl);
                }
                close(conn_fd);
                if (out_err) *out_err = EPROTO;
                return false;
        }
    }
}

void portillia_stream_client_drain(portillia_stream_client_t *s) {
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    while (s->accepted_count > 0) {
        portillia_net_conn_t *conn = s->accepted_conns[s->accepted_head];
        s->accepted_head = (s->accepted_head + 1) % s->accepted_cap;
        s->accepted_count--;
        if (conn) {
            portillia_net_conn_cleanup(conn);
            portillia_gc_free_later(conn);
        }
    }
    pthread_mutex_unlock(&s->mu);
}
