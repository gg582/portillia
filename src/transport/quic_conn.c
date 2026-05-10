#include <portillia/transport/quic_conn.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>
#include <portillia/mem/gc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <errno.h>

#if defined(__has_include)
  #if __has_include(<ngtcp2/ngtcp2.h>)
    #define HAS_NGTCP2 1
  #endif
#elif defined(__linux__) || defined(__APPLE__)
  #include <ngtcp2/ngtcp2.h>
  #define HAS_NGTCP2 1
#endif

#if HAS_NGTCP2

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define MAX_UDP_PAYLOAD 65535
#define NGTCP2_DEFAULT_MAX_DATAGRAM_FRAME_SIZE 1200

typedef struct {
    ngtcp2_conn *conn;
    ngtcp2_crypto_ossl_ctx *crypto_ctx;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int fd;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    ngtcp2_path_storage path;
    pthread_t thread;
    pthread_mutex_t mu;
    bool closed;
    bool handshake_done;

    /* Datagram send queue */
    pthread_mutex_t send_mu;
    pthread_cond_t send_cond;
    uint8_t *send_buf;
    size_t send_len;

    /* Receive callback */
    void (*recv_cb)(void *user_data, const uint8_t *data, size_t len);
    void *recv_user_data;

    ngtcp2_crypto_conn_ref conn_ref;
} quic_conn_internal_t;

/* ---------- Timestamp helpers ---------- */

static ngtcp2_tstamp timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * 1000000000ULL + (ngtcp2_tstamp)ts.tv_nsec;
}

/* ---------- ngtcp2 callbacks ---------- */

static int callback_client_initial(ngtcp2_conn *conn, void *user_data) {
    (void)user_data;
    return ngtcp2_crypto_client_initial_cb(conn, user_data);
}

static int callback_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                                      uint64_t offset, const uint8_t *data, size_t datalen,
                                      void *user_data) {
    (void)offset;
    return ngtcp2_crypto_recv_crypto_data_cb(conn, level, offset, data, datalen, user_data);
}

static int callback_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                                      uint64_t offset, const uint8_t *data, size_t datalen,
                                      void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)stream_id; (void)offset;
    (void)data; (void)datalen; (void)user_data; (void)stream_user_data;
    return 0;
}

static int callback_recv_datagram(ngtcp2_conn *conn, uint32_t flags,
                                   const uint8_t *data, size_t datalen,
                                   void *user_data) {
    (void)conn; (void)flags;
    quic_conn_internal_t *qc = (quic_conn_internal_t *)user_data;
    if (qc->recv_cb) {
        qc->recv_cb(qc->recv_user_data, data, datalen);
    }
    return 0;
}

static int callback_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    quic_conn_internal_t *qc = (quic_conn_internal_t *)user_data;
    pthread_mutex_lock(&qc->mu);
    qc->handshake_done = true;
    pthread_mutex_unlock(&qc->mu);
    LOG_INFO("QUIC handshake completed");
    return 0;
}

static void callback_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx) {
    (void)ctx;
    RAND_bytes(dest, (int)destlen);
}

static int callback_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                           uint8_t *token, size_t cidlen,
                                           void *user_data) {
    (void)conn; (void)token; (void)user_data;
    RAND_bytes(cid->data, (int)cidlen);
    cid->datalen = cidlen;
    return 0;
}

static ngtcp2_conn *conn_ref_get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    quic_conn_internal_t *qc = (quic_conn_internal_t *)conn_ref->user_data;
    return qc->conn;
}

/* ---------- I/O thread ---------- */

static void *quic_io_thread(void *arg) {
    quic_conn_internal_t *qc = arg;
    uint8_t rx_buf[MAX_UDP_PAYLOAD];
    uint8_t tx_buf[MAX_UDP_PAYLOAD];

    while (!qc->closed) {
        ngtcp2_tstamp ts = timestamp_ns();

        /* Handle timer expiry */
        ngtcp2_conn_handle_expiry(qc->conn, ts);

        /* Read incoming UDP */
        struct sockaddr_storage peer_addr;
        socklen_t peer_addrlen = sizeof(peer_addr);
        ssize_t n = recvfrom(qc->fd, rx_buf, sizeof(rx_buf), MSG_DONTWAIT,
                             (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (n > 0) {
            ngtcp2_path path = qc->path.path;
            path.remote.addr = (ngtcp2_sockaddr *)&peer_addr;
            path.remote.addrlen = (ngtcp2_socklen)peer_addrlen;
            ngtcp2_pkt_info pi = {0};
            ngtcp2_conn_read_pkt(qc->conn, &path, &pi, rx_buf, (size_t)n, ts);
        }

        /* Write general packets (ACKs, handshake, etc.) */
        while (!qc->closed) {
            ngtcp2_path_storage ps;
            ngtcp2_path_storage_init(&ps,
                qc->path.path.local.addr, qc->path.path.local.addrlen,
                qc->path.path.remote.addr, qc->path.path.remote.addrlen,
                NULL);
            ngtcp2_pkt_info pi = {0};
            ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(qc->conn, &ps.path, &pi,
                                                        tx_buf, sizeof(tx_buf), ts);
            if (nwrite <= 0) break;
            sendto(qc->fd, tx_buf, (size_t)nwrite, 0,
                   (struct sockaddr *)&qc->remote_addr, qc->remote_addrlen);
        }

        /* Send queued datagrams */
        pthread_mutex_lock(&qc->send_mu);
        uint8_t *dgram = qc->send_buf;
        size_t dgram_len = qc->send_len;
        qc->send_buf = NULL;
        qc->send_len = 0;
        pthread_mutex_unlock(&qc->send_mu);

        if (dgram && dgram_len > 0) {
            ngtcp2_path_storage ps;
            ngtcp2_path_storage_init(&ps,
                qc->path.path.local.addr, qc->path.path.local.addrlen,
                qc->path.path.remote.addr, qc->path.path.remote.addrlen,
                NULL);
            ngtcp2_pkt_info pi = {0};
            int accepted = 0;
            ngtcp2_ssize nwrite = ngtcp2_conn_write_datagram(
                qc->conn, &ps.path, &pi, tx_buf, sizeof(tx_buf), &accepted,
                0 /* flags */, 0 /* dgram_id */, dgram, dgram_len, ts);
            if (nwrite > 0) {
                sendto(qc->fd, tx_buf, (size_t)nwrite, 0,
                       (struct sockaddr *)&qc->remote_addr, qc->remote_addrlen);
            }
            free(dgram);
        }

        usleep(1000); /* 1ms loop */
    }
    return NULL;
}

/* ---------- Public API ---------- */

portillia_quic_conn_t *portillia_quic_conn_new(const char *host, int port) {
    if (!host || port <= 0) return NULL;

    /* Resolve host */
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        LOG_ERROR("QUIC: failed to resolve %s:%d", host, port);
        return NULL;
    }

    /* Create UDP socket */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return NULL;
    }

    quic_conn_internal_t *qc = calloc(1, sizeof(quic_conn_internal_t));
    if (!qc) {
        close(fd);
        freeaddrinfo(res);
        return NULL;
    }

    qc->fd = fd;
    memcpy(&qc->remote_addr, res->ai_addr, res->ai_addrlen);
    qc->remote_addrlen = res->ai_addrlen;
    freeaddrinfo(res);

    /* Get local address */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);
    if (getsockname(fd, (struct sockaddr *)&local_addr, &local_addrlen) < 0) {
        local_addrlen = 0;
    }

    /* Initialize path storage */
    ngtcp2_path_storage_init(&qc->path,
        (local_addrlen > 0) ? (ngtcp2_sockaddr *)&local_addr : NULL,
        (ngtcp2_socklen)local_addrlen,
        (ngtcp2_sockaddr *)&qc->remote_addr, (ngtcp2_socklen)qc->remote_addrlen,
        NULL);

    /* Generate CIDs */
    ngtcp2_cid dcid, scid;
    RAND_bytes(dcid.data, 8);
    dcid.datalen = 8;
    RAND_bytes(scid.data, 8);
    scid.datalen = 8;

    /* Set up callbacks */
    ngtcp2_callbacks callbacks = {0};
    callbacks.client_initial = callback_client_initial;
    callbacks.recv_crypto_data = callback_recv_crypto_data;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data = callback_recv_stream_data;
    callbacks.recv_datagram = callback_recv_datagram;
    callbacks.handshake_completed = callback_handshake_completed;
    callbacks.rand = callback_rand;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.get_new_connection_id = callback_get_new_connection_id;

    /* Set up settings */
    ngtcp2_settings settings;
    ngtcp2_settings_default_versioned(NGTCP2_SETTINGS_VERSION, &settings);

    /* Set up transport params */
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default_versioned(NGTCP2_TRANSPORT_PARAMS_VERSION, &params);
    params.initial_max_streams_uni = 0;
    params.initial_max_stream_data_bidi_local = 0;
    params.initial_max_stream_data_bidi_remote = 0;
    params.initial_max_data = 1048576;
    params.max_datagram_frame_size = NGTCP2_DEFAULT_MAX_DATAGRAM_FRAME_SIZE;

    /* Create ngtcp2 connection */
    int rv = ngtcp2_conn_client_new(
        &qc->conn, &dcid, &scid, &qc->path.path,
        NGTCP2_PROTO_VER_V1, &callbacks,
        &settings, &params, NULL, qc);
    if (rv != 0) {
        LOG_ERROR("QUIC: ngtcp2_conn_client_new failed: %d", rv);
        close(fd);
        free(qc);
        return NULL;
    }

    /* Set up OpenSSL */
    qc->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!qc->ssl_ctx) {
        LOG_ERROR("QUIC: SSL_CTX_new failed");
        ngtcp2_conn_del(qc->conn);
        close(fd);
        free(qc);
        return NULL;
    }
    if (portillia_network_configure_ssl_client_ctx(qc->ssl_ctx, false) != 0) {
        LOG_ERROR("QUIC: failed to configure TLS verification context");
        SSL_CTX_free(qc->ssl_ctx);
        ngtcp2_conn_del(qc->conn);
        close(fd);
        free(qc);
        return NULL;
    }

    qc->ssl = SSL_new(qc->ssl_ctx);
    if (!qc->ssl) {
        LOG_ERROR("QUIC: SSL_new failed");
        SSL_CTX_free(qc->ssl_ctx);
        ngtcp2_conn_del(qc->conn);
        close(fd);
        free(qc);
        return NULL;
    }
    if (!SSL_set_tlsext_host_name(qc->ssl, host) || !SSL_set1_host(qc->ssl, host)) {
        LOG_ERROR("QUIC: failed to configure SNI/hostname verification for %s", host);
        SSL_free(qc->ssl);
        SSL_CTX_free(qc->ssl_ctx);
        ngtcp2_conn_del(qc->conn);
        close(fd);
        free(qc);
        return NULL;
    }

    if (ngtcp2_crypto_ossl_ctx_new(&qc->crypto_ctx, qc->ssl) != 0) {
        LOG_ERROR("QUIC: ngtcp2_crypto_ossl_ctx_new failed");
        SSL_free(qc->ssl);
        SSL_CTX_free(qc->ssl_ctx);
        ngtcp2_conn_del(qc->conn);
        close(fd);
        free(qc);
        return NULL;
    }

    if (ngtcp2_crypto_ossl_configure_client_session(qc->ssl) != 0) {
        LOG_ERROR("QUIC: ngtcp2_crypto_ossl_configure_client_session failed");
        ngtcp2_crypto_ossl_ctx_del(qc->crypto_ctx);
        SSL_free(qc->ssl);
        SSL_CTX_free(qc->ssl_ctx);
        ngtcp2_conn_del(qc->conn);
        close(fd);
        free(qc);
        return NULL;
    }

    qc->conn_ref.get_conn = conn_ref_get_conn;
    qc->conn_ref.user_data = qc;
    SSL_set_app_data(qc->ssl, &qc->conn_ref);

    /* Initialize mutexes */
    pthread_mutex_init(&qc->mu, NULL);
    pthread_mutex_init(&qc->send_mu, NULL);
    pthread_cond_init(&qc->send_cond, NULL);

    /* Start I/O thread */
    if (pthread_create(&qc->thread, NULL, quic_io_thread, qc) != 0) {
        LOG_ERROR("QUIC: failed to create I/O thread");
        ngtcp2_crypto_ossl_ctx_del(qc->crypto_ctx);
        SSL_free(qc->ssl);
        SSL_CTX_free(qc->ssl_ctx);
        ngtcp2_conn_del(qc->conn);
        close(fd);
        free(qc);
        return NULL;
    }

    return (portillia_quic_conn_t *)qc;
}

void portillia_quic_conn_free(portillia_quic_conn_t *qc_) {
    quic_conn_internal_t *qc = (quic_conn_internal_t *)qc_;
    if (!qc) return;

    pthread_mutex_lock(&qc->mu);
    qc->closed = true;
    pthread_mutex_unlock(&qc->mu);

    pthread_cond_broadcast(&qc->send_cond);
    pthread_join(qc->thread, NULL);

    if (qc->conn) ngtcp2_conn_del(qc->conn);
    if (qc->crypto_ctx) ngtcp2_crypto_ossl_ctx_del(qc->crypto_ctx);
    if (qc->ssl) SSL_free(qc->ssl);
    if (qc->ssl_ctx) SSL_CTX_free(qc->ssl_ctx);
    if (qc->fd >= 0) close(qc->fd);
    free(qc->send_buf);

    pthread_mutex_destroy(&qc->mu);
    pthread_mutex_destroy(&qc->send_mu);
    pthread_cond_destroy(&qc->send_cond);
    free(qc);
}

int portillia_quic_conn_send_datagram(portillia_quic_conn_t *qc_, const uint8_t *data, size_t len) {
    quic_conn_internal_t *qc = (quic_conn_internal_t *)qc_;
    if (!qc || qc->closed || !data) return -1;

    pthread_mutex_lock(&qc->send_mu);
    free(qc->send_buf);
    qc->send_buf = malloc(len);
    if (!qc->send_buf) {
        pthread_mutex_unlock(&qc->send_mu);
        return -1;
    }
    memcpy(qc->send_buf, data, len);
    qc->send_len = len;
    pthread_cond_signal(&qc->send_cond);
    pthread_mutex_unlock(&qc->send_mu);
    return 0;
}

void portillia_quic_conn_set_recv_handler(portillia_quic_conn_t *qc_,
    void (*cb)(void *user_data, const uint8_t *data, size_t len), void *user_data) {
    quic_conn_internal_t *qc = (quic_conn_internal_t *)qc_;
    if (!qc) return;
    pthread_mutex_lock(&qc->mu);
    qc->recv_cb = cb;
    qc->recv_user_data = user_data;
    pthread_mutex_unlock(&qc->mu);
}

bool portillia_quic_conn_handshake_done(portillia_quic_conn_t *qc_) {
    quic_conn_internal_t *qc = (quic_conn_internal_t *)qc_;
    if (!qc) return false;
    pthread_mutex_lock(&qc->mu);
    bool done = qc->handshake_done;
    pthread_mutex_unlock(&qc->mu);
    return done;
}

#else /* !HAS_NGTCP2 */

/* Stubs when ngtcp2 is unavailable */

portillia_quic_conn_t *portillia_quic_conn_new(const char *host, int port) {
    (void)host; (void)port;
    LOG_WARN("QUIC support is not available (ngtcp2 not found)");
    return NULL;
}

void portillia_quic_conn_free(portillia_quic_conn_t *qc_) {
    (void)qc_;
}

int portillia_quic_conn_send_datagram(portillia_quic_conn_t *qc_, const uint8_t *data, size_t len) {
    (void)qc_; (void)data; (void)len;
    return -1;
}

void portillia_quic_conn_set_recv_handler(portillia_quic_conn_t *qc_,
    void (*cb)(void *user_data, const uint8_t *data, size_t len), void *user_data) {
    (void)qc_; (void)cb; (void)user_data;
}

bool portillia_quic_conn_handshake_done(portillia_quic_conn_t *qc_) {
    (void)qc_;
    return false;
}

#endif
