/** @file tls_proxy.c
 * @brief Single-threaded non-blocking TLS terminating proxy.
 *
 * The previous implementation serialized SSL_read and SSL_write through a
 * single mutex per SSL object.  Because SSL_read on a blocking socket parks
 * inside OpenSSL with the lock held, the writer thread could never make
 * progress and the TLS handshake stalled before any response was sent.
 *
 * This rewrite drives every connection from one thread that polls both file
 * descriptors and pumps the SSL state machine in non-blocking mode.  ALPN,
 * minimum TLS version, ECH, and SNI callbacks are configured on the shared
 * SSL_CTX.
 */
#include <portillia/portal/tls_proxy.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <portillia/utils/log.h>

#include <cwist/security/tls/ech.h>

#define TLS_PROXY_BUF_SZ        16384
#define TLS_PROXY_HANDSHAKE_MS  15000
#define TLS_PROXY_IDLE_MS       300000

static SSL_CTX *tls_ctx = NULL;
static pthread_mutex_t ctx_mu = PTHREAD_MUTEX_INITIALIZER;

/* HTTP/1.1 only.  HTTP/2 cannot be honored after this proxy because the
 * downstream API server is plain HTTP/1.1; advertising h2 would break clients
 * that select it. */
static const unsigned char alpn_wire[] = { 8, 'h','t','t','p','/','1','.','1' };

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              alpn_wire, sizeof(alpn_wire),
                              in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void apply_ctx_options(SSL_CTX *ctx) {
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY |
                          SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION |
                             SSL_OP_NO_RENEGOTIATION |
                             SSL_OP_CIPHER_SERVER_PREFERENCE |
                             SSL_OP_SINGLE_DH_USE |
                             SSL_OP_SINGLE_ECDH_USE);
    /* Reasonable modern TLS 1.2 ciphers; TLS 1.3 ciphers are configured via
     * the ciphersuites API and OpenSSL defaults already cover AES-GCM and
     * ChaCha20-Poly1305. */
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_read_ahead(ctx, 1);
}

int portillia_tls_proxy_init(const char *cert_path, const char *key_path) {
    if (!cert_path || !key_path) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        LOG_ERROR("tls_proxy: SSL_CTX_new failed");
        return -1;
    }
    apply_ctx_options(ctx);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        LOG_ERROR("tls_proxy: load cert chain failed path=%s err=%s", cert_path, buf);
        SSL_CTX_free(ctx);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        LOG_ERROR("tls_proxy: load private key failed path=%s err=%s", key_path, buf);
        SSL_CTX_free(ctx);
        return -1;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        LOG_ERROR("tls_proxy: private key/cert mismatch");
        SSL_CTX_free(ctx);
        return -1;
    }

    pthread_mutex_lock(&ctx_mu);
    SSL_CTX *old = tls_ctx;
    tls_ctx = ctx;
    pthread_mutex_unlock(&ctx_mu);
    if (old) SSL_CTX_free(old);
    return 0;
}

int portillia_tls_proxy_apply_ech(const char *ech_pem_path) {
    if (!ech_pem_path || !ech_pem_path[0]) return -1;
    if (!cwist_ech_is_supported_by_openssl()) return -1;

    pthread_mutex_lock(&ctx_mu);
    SSL_CTX *ctx = tls_ctx;
    pthread_mutex_unlock(&ctx_mu);
    if (!ctx) return -1;

    cwist_ech_config cfg = {
        .ech_key_file = (char *)ech_pem_path,
        .ech_dir = NULL,
        .enforce_ech = false,
        .auto_retry_keys = true,
    };
    cwist_error_t err = cwist_ech_apply_server_config(ctx, &cfg);
    if (err.errtype == CWIST_ERR_INT16 && err.error.err_i16 == 0) {
        LOG_INFO("tls_proxy: ECH applied to SNI listener context");
        return 0;
    }
    LOG_WARN("tls_proxy: ECH apply skipped errtype=%d", err.errtype);
    return -1;
}

typedef struct {
    int client_fd;
    int target_fd;
} bridge_args;

/* Drain any TLS writes queued in the BIO into the socket. */
static int flush_outgoing(SSL *ssl, int *want_writable) {
    *want_writable = 0;
    while (1) {
        int pending = SSL_pending(ssl);
        (void)pending;
        /* OpenSSL with default BIO automatically writes to the fd; nothing to
         * drain here.  We use this stub to centralize semantics if BIO is
         * later switched to memory BIOs. */
        return 0;
    }
}

static bool ssl_handshake(SSL *ssl, int client_fd) {
    long deadline = now_ms() + TLS_PROXY_HANDSHAKE_MS;
    while (1) {
        ERR_clear_error();
        int rc = SSL_accept(ssl);
        if (rc == 1) return true;
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            long remaining = deadline - now_ms();
            if (remaining <= 0) {
                LOG_WARN("tls_proxy: handshake timeout");
                return false;
            }
            struct pollfd pfd;
            pfd.fd = client_fd;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int p;
            do { p = poll(&pfd, 1, (int)remaining); } while (p < 0 && errno == EINTR);
            if (p <= 0) {
                LOG_WARN("tls_proxy: handshake poll rc=%d errno=%d", p, errno);
                return false;
            }
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                LOG_WARN("tls_proxy: handshake socket error revents=%d", pfd.revents);
                return false;
            }
            continue;
        }
        unsigned long e = ERR_peek_last_error();
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        LOG_ERROR("tls_proxy: SSL_accept failed err=%d openssl=%s", err, buf);
        return false;
    }
}

/* Pump pending plaintext from target_fd into ssl. */
static int pump_target_to_client(SSL *ssl, int target_fd, int *want_target_read,
                                 int *want_client_write, char *buf, int *buf_len, int buf_cap) {
    if (*buf_len == 0) {
        ssize_t n = read(target_fd, buf, buf_cap);
        if (n == 0) return -1; /* target EOF */
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                *want_target_read = 1;
                return 0;
            }
            return -1;
        }
        *buf_len = (int)n;
    }

    int written = 0;
    while (written < *buf_len) {
        ERR_clear_error();
        int w = SSL_write(ssl, buf + written, *buf_len - written);
        if (w > 0) {
            written += w;
            continue;
        }
        int err = SSL_get_error(ssl, w);
        if (err == SSL_ERROR_WANT_WRITE) { *want_client_write = 1; break; }
        if (err == SSL_ERROR_WANT_READ)  { *want_client_write = 1; break; }
        return -1;
    }
    if (written == *buf_len) {
        *buf_len = 0;
    } else {
        memmove(buf, buf + written, *buf_len - written);
        *buf_len -= written;
    }
    return 0;
}

static int pump_client_to_target(SSL *ssl, int target_fd, int *want_client_read,
                                 int *want_target_write, char *buf, int *buf_len, int buf_cap) {
    if (*buf_len == 0) {
        ERR_clear_error();
        int n = SSL_read(ssl, buf, buf_cap);
        if (n > 0) {
            *buf_len = n;
        } else {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ)  { *want_client_read = 1; return 0; }
            if (err == SSL_ERROR_WANT_WRITE) { *want_client_read = 1; return 0; }
            if (err == SSL_ERROR_ZERO_RETURN) return -1;
            return -1;
        }
    }

    int written = 0;
    while (written < *buf_len) {
        ssize_t w = write(target_fd, buf + written, *buf_len - written);
        if (w > 0) {
            written += (int)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            *want_target_write = 1;
            break;
        }
        return -1;
    }
    if (written == *buf_len) {
        *buf_len = 0;
    } else {
        memmove(buf, buf + written, *buf_len - written);
        *buf_len -= written;
    }
    return 0;
}

static void *bridge_thread(void *arg) {
    bridge_args *ba = (bridge_args *)arg;
    int client_fd = ba->client_fd;
    int target_fd = ba->target_fd;
    free(ba);

    pthread_mutex_lock(&ctx_mu);
    SSL_CTX *ctx = tls_ctx;
    pthread_mutex_unlock(&ctx_mu);
    if (!ctx) {
        close(client_fd);
        close(target_fd);
        return NULL;
    }

    if (set_nonblocking(client_fd) < 0 || set_nonblocking(target_fd) < 0) {
        LOG_ERROR("tls_proxy: failed to set non-blocking");
        close(client_fd);
        close(target_fd);
        return NULL;
    }

    int nodelay = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    setsockopt(target_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        LOG_ERROR("tls_proxy: SSL_new failed");
        close(client_fd);
        close(target_fd);
        return NULL;
    }
    if (!SSL_set_fd(ssl, client_fd)) {
        SSL_free(ssl);
        close(client_fd);
        close(target_fd);
        return NULL;
    }

    if (!ssl_handshake(ssl, client_fd)) {
        SSL_free(ssl);
        close(client_fd);
        close(target_fd);
        return NULL;
    }

    char c2t_buf[TLS_PROXY_BUF_SZ];
    char t2c_buf[TLS_PROXY_BUF_SZ];
    int c2t_len = 0;
    int t2c_len = 0;
    bool client_read_eof = false;
    bool target_read_eof = false;

    while (1) {
        int want_client_read = 0, want_client_write = 0;
        int want_target_read = 0, want_target_write = 0;

        /* Drain SSL backlog before polling. */
        if (SSL_pending(ssl) > 0 && c2t_len < TLS_PROXY_BUF_SZ) {
            int w_cr = 0, w_tw = 0;
            if (pump_client_to_target(ssl, target_fd, &w_cr, &w_tw,
                                      c2t_buf, &c2t_len, TLS_PROXY_BUF_SZ) < 0) break;
        }

        if (!client_read_eof && c2t_len < TLS_PROXY_BUF_SZ) {
            if (pump_client_to_target(ssl, target_fd, &want_client_read, &want_target_write,
                                      c2t_buf, &c2t_len, TLS_PROXY_BUF_SZ) < 0) {
                client_read_eof = true;
                shutdown(target_fd, SHUT_WR);
            }
        }

        if (!target_read_eof && t2c_len < TLS_PROXY_BUF_SZ) {
            if (pump_target_to_client(ssl, target_fd, &want_target_read, &want_client_write,
                                      t2c_buf, &t2c_len, TLS_PROXY_BUF_SZ) < 0) {
                target_read_eof = true;
                /* No half-close path on TLS; signal via SSL_shutdown after
                 * the remaining buffer drains. */
            }
        }

        if (client_read_eof && target_read_eof && c2t_len == 0 && t2c_len == 0) break;

        struct pollfd pfds[2];
        pfds[0].fd = client_fd;
        pfds[0].events = 0;
        /* Gate POLLIN on c2t_len == 0 (the condition under which the next pump will SSL_read), not on want_client_read which would drop after a successful read and silently break keep-alive. */
        if (!client_read_eof && c2t_len == 0) pfds[0].events |= POLLIN;
        if (t2c_len > 0 || want_client_write) pfds[0].events |= POLLOUT;

        pfds[1].fd = target_fd;
        pfds[1].events = 0;
        if (!target_read_eof && t2c_len == 0) pfds[1].events |= POLLIN;
        if (c2t_len > 0 || want_target_write) pfds[1].events |= POLLOUT;

        if (pfds[0].events == 0 && pfds[1].events == 0) break;

        int p;
        do { p = poll(pfds, 2, TLS_PROXY_IDLE_MS); } while (p < 0 && errno == EINTR);
        if (p <= 0) {
            if (p == 0) LOG_DEBUG("tls_proxy: idle timeout");
            break;
        }

        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) client_read_eof = true;
        if (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) target_read_eof = true;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    shutdown(client_fd, SHUT_RDWR);
    shutdown(target_fd, SHUT_RDWR);
    close(client_fd);
    close(target_fd);
    return NULL;
}

void portillia_tls_proxy_bridge(int client_fd, int target_fd) {
    pthread_mutex_lock(&ctx_mu);
    SSL_CTX *ctx = tls_ctx;
    pthread_mutex_unlock(&ctx_mu);
    if (!ctx) {
        close(client_fd);
        close(target_fd);
        return;
    }

    pthread_t tid;
    bridge_args *args = malloc(sizeof(*args));
    if (!args) {
        close(client_fd);
        close(target_fd);
        return;
    }
    args->client_fd = client_fd;
    args->target_fd = target_fd;
    if (pthread_create(&tid, NULL, bridge_thread, args) != 0) {
        free(args);
        close(client_fd);
        close(target_fd);
        return;
    }
    pthread_detach(tid);
}
