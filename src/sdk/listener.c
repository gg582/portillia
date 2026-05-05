/** @file listener.c
 * @brief Single relay listener implementation with register/renew/run loop.
 */

#include <portillia/sdk/listener.h>
#include <portillia/portal/keyless/tls.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

/* ---------- Constants ---------- */

#define DEFAULT_DIAL_TIMEOUT_SEC      5
#define DEFAULT_REQUEST_TIMEOUT_SEC   15
#define DEFAULT_HANDSHAKE_TIMEOUT_SEC 15
#define DEFAULT_LEASE_TTL_SEC         30
#define DEFAULT_RENEW_BEFORE_SEC      5
#define DEFAULT_READY_TARGET          2
#define DEFAULT_RETRY_WAIT_SEC        3

/* ---------- Lease helpers ---------- */

static void lease_cleanup(portillia_listener_lease_t *lease) {
    if (!lease) return;
    if (lease->hostname) portillia_gc_free_later(lease->hostname);
    if (lease->udp_addr) portillia_gc_free_later(lease->udp_addr);
    if (lease->tcp_addr) portillia_gc_free_later(lease->tcp_addr);
    if (lease->access_token) portillia_gc_free_later(lease->access_token);
    if (lease->hop_routes) {
        for (size_t i = 0; i < lease->hop_routes_count; i++) {
            portillia_hop_route_cleanup(&lease->hop_routes[i]);
        }
        portillia_gc_free_later(lease->hop_routes);
    }
    if (lease->tls_ctx) {
        SSL_CTX_free((SSL_CTX *)lease->tls_ctx);
    }
    memset(lease, 0, sizeof(*lease));
}

static portillia_listener_lease_t *lease_snapshot(portillia_listener_t *l) {
    pthread_mutex_lock(&l->lease_mu);
    portillia_listener_lease_t *lease = l->lease;
    pthread_mutex_unlock(&l->lease_mu);
    return lease;
}

static void set_lease(portillia_listener_t *l, portillia_listener_lease_t *new_lease) {
    pthread_mutex_lock(&l->lease_mu);
    portillia_listener_lease_t *old = l->lease;
    l->lease = new_lease;
    pthread_mutex_unlock(&l->lease_mu);
    if (old) {
        lease_cleanup(old);
        portillia_gc_free_later(old);
    }
}

static void clear_lease(portillia_listener_t *l) {
    set_lease(l, NULL);
    if (l->datagram) portillia_datagram_client_clear(l->datagram, "lease cleared");
}

/* ---------- Reverse session ---------- */

static int parse_relay_host_port(const char *relay_url, char *host, size_t host_len, int *port) {
    if (!relay_url || !host || !port) return -1;
    (void)host_len;
    *port = 443;
    if (sscanf(relay_url, "https://%255[^:/]:%d", host, port) >= 1) return 0;
    if (sscanf(relay_url, "http://%255[^:/]:%d", host, port) >= 1) {
        if (*port == 443) *port = 80;
        return 0;
    }
    if (sscanf(relay_url, "https://%255[^/]", host) == 1) return 0;
    if (sscanf(relay_url, "http://%255[^/]", host) == 1) {
        *port = 80;
        return 0;
    }
    return -1;
}

static bool is_https_url(const char *url) {
    return url && strncmp(url, "https://", 8) == 0;
}

static int open_reverse_session(portillia_listener_t *l, SSL **out_outer_ssl) {
    if (out_outer_ssl) *out_outer_ssl = NULL;
    portillia_listener_lease_t *lease = lease_snapshot(l);
    if (!lease || !lease->access_token) {
        errno = EINVAL;
        return -1;
    }

    char host[256] = {0};
    int port = 0;
    if (parse_relay_host_port(l->relay_url, host, sizeof(host), &port) != 0) {
        errno = EINVAL;
        return -1;
    }

    struct hostent *server = gethostbyname(host);
    if (!server) {
        errno = EHOSTUNREACH;
        return -1;
    }

    int conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn_fd < 0) return -1;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((uint16_t)port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, (size_t)server->h_length);

    if (connect(conn_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(conn_fd);
        return -1;
    }

    SSL *outer_ssl = NULL;
    if (is_https_url(l->relay_url)) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            close(conn_fd);
            return -1;
        }
        if (portillia_network_configure_ssl_client_ctx(ctx, l->insecure_skip_verify) != 0) {
            SSL_CTX_free(ctx);
            close(conn_fd);
            errno = EIO;
            return -1;
        }
        outer_ssl = SSL_new(ctx);
        SSL_CTX_free(ctx);
        if (!outer_ssl) {
            close(conn_fd);
            return -1;
        }
        if (!SSL_set_fd(outer_ssl, conn_fd)) {
            SSL_free(outer_ssl);
            close(conn_fd);
            return -1;
        }
        if (!SSL_set_tlsext_host_name(outer_ssl, host)) {
            SSL_free(outer_ssl);
            close(conn_fd);
            errno = EIO;
            return -1;
        }
        if (!l->insecure_skip_verify && !SSL_set1_host(outer_ssl, host)) {
            SSL_free(outer_ssl);
            close(conn_fd);
            errno = EIO;
            return -1;
        }
        if (SSL_connect(outer_ssl) <= 0) {
            SSL_free(outer_ssl);
            close(conn_fd);
            errno = EIO;
            return -1;
        }
    }

    char req[1024];
    int req_len = snprintf(
        req, sizeof(req),
        "GET /sdk/connect HTTP/1.1\r\n"
        "Host: %s\r\n"
        "X-Portal-Access-Token: %s\r\n"
        "Connection: keep-alive\r\n\r\n",
        host, lease->access_token
    );
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        if (outer_ssl) SSL_free(outer_ssl);
        close(conn_fd);
        errno = EOVERFLOW;
        return -1;
    }

    if (outer_ssl) {
        if (SSL_write(outer_ssl, req, req_len) != req_len) {
            SSL_free(outer_ssl);
            close(conn_fd);
            errno = EIO;
            return -1;
        }
    } else {
        if (write(conn_fd, req, (size_t)req_len) != req_len) {
            close(conn_fd);
            errno = EIO;
            return -1;
        }
    }

    char resp[1024];
    ssize_t nr;
    if (outer_ssl) {
        nr = SSL_read(outer_ssl, resp, sizeof(resp) - 1);
    } else {
        nr = read(conn_fd, resp, sizeof(resp) - 1);
    }
    if (nr <= 0) {
        if (outer_ssl) SSL_free(outer_ssl);
        close(conn_fd);
        errno = EIO;
        return -1;
    }
    resp[nr] = '\0';
    if (!strstr(resp, " 200 ") && !strstr(resp, " 200\r") && !strstr(resp, " 200\n")) {
        if (outer_ssl) SSL_free(outer_ssl);
        close(conn_fd);
        errno = EACCES;
        return -1;
    }

    if (out_outer_ssl) *out_outer_ssl = outer_ssl;
    return conn_fd;
}

static void *reverse_session_thread(void *arg) {
    portillia_listener_t *l = (portillia_listener_t *)arg;
    int retries = 0;

    while (!l->cancelled) {
        SSL *outer_ssl = NULL;
        int conn_fd = open_reverse_session(l, &outer_ssl);
        if (conn_fd < 0) {
            if (l->cancelled) break;
            retries++;
            if (l->retry_count > 0 && retries > l->retry_count) {
                LOG_ERROR("SDK: Reverse session retry budget exhausted for %s", l->relay_url);
                pthread_mutex_lock(&l->run_err_mu);
                if (l->run_err == 0) l->run_err = ECONNRESET;
                pthread_cond_broadcast(&l->run_err_cond);
                pthread_mutex_unlock(&l->run_err_mu);
                break;
            }
            LOG_DEBUG("SDK: Reverse session connect failed for %s, retrying (%d/%d)",
                      l->relay_url, retries, l->retry_count);
            sleep(l->retry_wait_sec);
            continue;
        }

        retries = 0;
        int err = 0;
        portillia_listener_lease_t *lease = lease_snapshot(l);
        SSL_CTX *inner_ctx = lease ? (SSL_CTX *)lease->tls_ctx : NULL;
        bool claimed = portillia_stream_client_run_session(l->stream, conn_fd, outer_ssl, inner_ctx, &err);
        if (err == EPIPE || err == ECONNRESET) {
            continue; /* reconnect */
        }
        if (claimed) {
            continue; /* session claimed, open new one */
        }
        if (l->cancelled) break;
    }

    return NULL;
}

/* ---------- Renew loop ---------- */

static void *renew_thread(void *arg) {
    portillia_listener_t *l = (portillia_listener_t *)arg;
    int interval_sec = l->lease_ttl_sec / 2;
    if (l->renew_before_sec > 0 && l->renew_before_sec < l->lease_ttl_sec) {
        interval_sec = l->lease_ttl_sec - l->renew_before_sec;
    }

    while (!l->cancelled) {
        sleep(interval_sec);
        if (l->cancelled) break;

        portillia_listener_lease_t *lease = lease_snapshot(l);
        if (!lease || !lease->access_token) {
            LOG_WARN("SDK: No lease to renew for %s", l->relay_url);
            continue;
        }

        portillia_renew_response_t resp = {0};
        int retries = 0;
        while (!l->cancelled) {
            int rc = portillia_api_renew_lease(l->http_client, l->lease_ttl_sec,
                                                lease->access_token, &l->identity, l->relay_set,
                                                lease->hop_routes, lease->hop_routes_count, &resp);
            if (rc == 0) {
                /* Update lease access token */
                pthread_mutex_lock(&l->lease_mu);
                if (l->lease) {
                    if (l->lease->access_token) portillia_gc_free_later(l->lease->access_token);
                    l->lease->access_token = portillia_gc_strdup(resp.access_token);
                    l->lease->expires_at = resp.expires_at;
                }
                pthread_mutex_unlock(&l->lease_mu);
                LOG_INFO("SDK: Lease renewed for %s", l->relay_url);
                break;
            }

            retries++;
            if (l->retry_count > 0 && retries > l->retry_count) {
                LOG_ERROR("SDK: Lease renewal retry budget exhausted for %s", l->relay_url);
                pthread_mutex_lock(&l->run_err_mu);
                if (l->run_err == 0) l->run_err = EACCES;
                pthread_cond_broadcast(&l->run_err_cond);
                pthread_mutex_unlock(&l->run_err_mu);
                break;
            }
            LOG_DEBUG("SDK: Lease renewal failed for %s, retrying (%d/%d)",
                      l->relay_url, retries, l->retry_count);
            sleep(l->retry_wait_sec);
        }

        portillia_renew_response_cleanup(&resp);
    }

    return NULL;
}

/* ---------- Register & configure ---------- */

static int register_and_configure(portillia_listener_t *l) {
    if (!l->http_client) {
        l->http_client = portillia_http_client_create(l->relay_url, l->insecure_skip_verify);
        if (!l->http_client) return -1;
    }
    if (portillia_http_client_check_domain(l->http_client) != 0) {
        return -1;
    }

    portillia_register_response_t resp = {0};
    portillia_hop_route_t *hops = NULL;
    size_t hop_count = 0;

    int rc = portillia_api_register_lease(
        l->http_client, &l->identity, &l->metadata, l->relay_set,
        (const char **)l->multi_hop, l->multi_hop_count,
        l->lease_ttl_sec, l->udp_enabled, l->tcp_enabled,
        &resp, &hops, &hop_count
    );
    if (rc != 0) {
        LOG_ERROR("SDK: Failed to register lease for %s", l->relay_url);
        return -1;
    }

    /* Build inner TLS context from keyless config */
    const char *keyless_url = resp.keyless_url;
    if (!keyless_url || !keyless_url[0]) {
        keyless_url = l->relay_url;
    }
    void *tls_ctx = portillia_keyless_build_tls_ctx(keyless_url, resp.hostname, l->insecure_skip_verify);

    /* Store lease */
    portillia_listener_lease_t *lease = PORTILLIA_GC_NEW_ZERO(portillia_listener_lease_t);
    lease->hostname = portillia_gc_strdup(resp.hostname);
    lease->udp_addr = portillia_gc_strdup(resp.udp_addr);
    lease->tcp_addr = portillia_gc_strdup(resp.tcp_addr);
    lease->access_token = portillia_gc_strdup(resp.access_token);
    lease->expires_at = resp.expires_at;
    lease->sni_port = resp.sni_port;
    lease->hop_routes = hops;
    lease->hop_routes_count = hop_count;
    lease->tls_ctx = tls_ctx;
    set_lease(l, lease);

    /* Confirm relay in discovery set */
    if (l->relay_set) {
        portillia_relay_set_confirm_url(l->relay_set, l->relay_url);
    }

    LOG_INFO("SDK: Listener registered for %s -> %s", l->relay_url, resp.hostname ? resp.hostname : "(none)");

    /* Cleanup response */
    portillia_register_response_cleanup(&resp);
    return 0;
}

/* ---------- Run lease ---------- */

static int run_lease(portillia_listener_t *l) {
    portillia_listener_lease_t *lease = lease_snapshot(l);
    if (!lease || !lease->hostname) {
        return -1; /* errLeaseRefreshRequired */
    }

    /* Reset error state for this lease run */
    pthread_mutex_lock(&l->run_err_mu);
    l->run_err = 0;
    pthread_mutex_unlock(&l->run_err_mu);

    pthread_t *reverse_tids = NULL;
    int reverse_count = 0;
    pthread_t renew_tid;
    bool renew_started = false;

    if (l->stream && l->ready_target > 0) {
        reverse_tids = (pthread_t *)portillia_gc_alloc(sizeof(pthread_t) * l->ready_target);
        if (reverse_tids) {
            for (int i = 0; i < l->ready_target && !l->cancelled; i++) {
                if (pthread_create(&reverse_tids[i], NULL, reverse_session_thread, l) == 0) {
                    reverse_count++;
                }
            }
        }
    }

    if (!l->cancelled) {
        if (pthread_create(&renew_tid, NULL, renew_thread, l) == 0) {
            renew_started = true;
        }
    }

    /* Wait for error from any thread or cancellation */
    pthread_mutex_lock(&l->run_err_mu);
    while (!l->cancelled && l->run_err == 0) {
        pthread_cond_wait(&l->run_err_cond, &l->run_err_mu);
    }
    int err = l->run_err;
    pthread_mutex_unlock(&l->run_err_mu);

    /* Cleanup threads */
    for (int i = 0; i < reverse_count; i++) {
        pthread_join(reverse_tids[i], NULL);
    }
    if (reverse_tids) portillia_gc_free_later(reverse_tids);
    if (renew_started) pthread_join(renew_tid, NULL);

    return err;
}

/* ---------- Main run thread ---------- */

static void *listener_run_thread(void *arg) {
    portillia_listener_t *l = (portillia_listener_t *)arg;
    LOG_INFO("SDK: Listener thread started for %s", l->relay_url ? l->relay_url : "(none)");

    int retries = 0;
    while (!l->cancelled) {
        int err = register_and_configure(l);
        if (err != 0) {
            if (l->cancelled) break;
            retries++;
            if (l->retry_count > 0 && retries > l->retry_count) {
                LOG_ERROR("SDK: Registration retry budget exhausted for %s", l->relay_url);
                break;
            }
            LOG_DEBUG("SDK: Registration failed for %s, retrying (%d/%d)",
                      l->relay_url, retries, l->retry_count);
            sleep(l->retry_wait_sec);
            continue;
        }

        retries = 0;
        LOG_INFO("SDK: Service ready at %s", l->relay_url);

        err = run_lease(l);
        if (err != 0) {
            clear_lease(l);
            if (l->stream) portillia_stream_client_drain(l->stream);
            LOG_DEBUG("SDK: Lease refresh required for %s, re-registering", l->relay_url);
            continue;
        }

        if (l->cancelled) break;
    }

    LOG_INFO("SDK: Listener thread stopped for %s", l->relay_url ? l->relay_url : "(none)");
    return NULL;
}

/* ---------- Lifecycle ---------- */

portillia_listener_t *portillia_listener_new(const char *relay_url,
                                              const portillia_identity_t *identity,
                                              const portillia_lease_metadata_t *metadata,
                                              portillia_relay_set_t *relay_set,
                                              char **multi_hop, size_t multi_hop_count,
                                              bool udp_enabled, bool tcp_enabled,
                                              int retry_count,
                                              bool insecure_skip_verify) {
    if (!relay_url || !identity) {
        errno = EINVAL;
        return NULL;
    }

    portillia_listener_t *l = PORTILLIA_GC_NEW_ZERO(portillia_listener_t);
    if (!l) {
        errno = ENOMEM;
        return NULL;
    }

    l->relay_url = portillia_gc_strdup(relay_url);
    portillia_identity_copy(&l->identity, identity);
    if (metadata) portillia_lease_metadata_copy(&l->metadata, metadata);
    l->relay_set = relay_set;
    if (multi_hop_count > 0 && multi_hop) {
        l->multi_hop = (char **)portillia_gc_alloc(sizeof(char *) * multi_hop_count);
        if (l->multi_hop) {
            l->multi_hop_count = multi_hop_count;
            for (size_t i = 0; i < multi_hop_count; i++) {
                l->multi_hop[i] = multi_hop[i] ? portillia_gc_strdup(multi_hop[i]) : NULL;
            }
        }
    }
    l->udp_enabled = udp_enabled;
    l->tcp_enabled = tcp_enabled;
    l->ready_target = DEFAULT_READY_TARGET;
    l->retry_count = retry_count;
    l->retry_wait_sec = DEFAULT_RETRY_WAIT_SEC;
    l->lease_ttl_sec = DEFAULT_LEASE_TTL_SEC;
    l->renew_before_sec = DEFAULT_RENEW_BEFORE_SEC;
    l->insecure_skip_verify = insecure_skip_verify;

    l->stream = portillia_stream_client_new(l->ready_target, DEFAULT_HANDSHAKE_TIMEOUT_SEC);
    if (udp_enabled) {
        l->datagram = portillia_datagram_client_new(NULL);
    }

    pthread_mutex_init(&l->lease_mu, NULL);
    pthread_mutex_init(&l->run_err_mu, NULL);
    pthread_cond_init(&l->run_err_cond, NULL);

    if (pthread_create(&l->run_tid, NULL, listener_run_thread, l) != 0) {
        portillia_listener_close(l);
        errno = EAGAIN;
        return NULL;
    }

    return l;
}

void portillia_listener_close(portillia_listener_t *l) {
    if (!l) return;
    l->cancelled = true;
    pthread_join(l->run_tid, NULL);

    clear_lease(l);

    if (l->stream) {
        portillia_stream_client_destroy(l->stream);
        l->stream = NULL;
    }
    if (l->datagram) {
        portillia_datagram_client_destroy(l->datagram);
        l->datagram = NULL;
    }
    if (l->http_client) {
        portillia_http_client_destroy(l->http_client);
        l->http_client = NULL;
    }

    pthread_mutex_destroy(&l->lease_mu);

    if (l->relay_url) portillia_gc_free_later(l->relay_url);
    portillia_identity_cleanup(&l->identity);
    portillia_lease_metadata_cleanup(&l->metadata);
    if (l->multi_hop) {
        for (size_t i = 0; i < l->multi_hop_count; i++) {
            if (l->multi_hop[i]) portillia_gc_free_later(l->multi_hop[i]);
        }
        portillia_gc_free_later(l->multi_hop);
    }

    portillia_gc_free_later(l);
}

/* ---------- I/O ---------- */

portillia_net_conn_t *portillia_listener_accept(portillia_listener_t *l) {
    if (!l || l->cancelled) {
        errno = EBADF;
        return NULL;
    }
    if (!l->stream) {
        errno = EBADF;
        return NULL;
    }
    bool cancelled = false;
    return portillia_stream_client_accept(l->stream, &cancelled);
}

int portillia_listener_accept_datagram(portillia_listener_t *l, portillia_datagram_frame_t *out, bool *out_cancelled) {
    if (!l || l->cancelled || !out) {
        errno = EBADF;
        return -1;
    }
    if (!l->datagram) {
        errno = EBADF;
        return -1;
    }
    return portillia_datagram_client_accept(l->datagram, out, out_cancelled);
}

int portillia_listener_send_datagram(portillia_listener_t *l, const portillia_datagram_frame_t *frame) {
    if (!l || l->cancelled || !frame) {
        errno = EBADF;
        return -1;
    }
    if (!l->datagram) {
        errno = EBADF;
        return -1;
    }
    return portillia_datagram_client_send(l->datagram, frame->flow_id, frame->payload, frame->payload_len);
}

char *portillia_listener_datagram_ready(portillia_listener_t *l, bool *out_ready, bool *out_pending) {
    if (!l) {
        if (out_ready) *out_ready = false;
        if (out_pending) *out_pending = false;
        return NULL;
    }
    if (out_ready) *out_ready = false;
    if (out_pending) *out_pending = false;
    if (!l->datagram) return NULL;

    bool connected = portillia_datagram_client_connected(l->datagram);
    portillia_listener_lease_t *lease = lease_snapshot(l);
    bool has_udp = lease && lease->udp_addr && lease->udp_addr[0];
    bool has_hostname = lease && lease->hostname && lease->hostname[0];

    if (connected && has_udp) {
        if (out_ready) *out_ready = true;
        return portillia_gc_strdup(lease->udp_addr);
    }
    if (!l->cancelled && (!has_hostname || has_udp)) {
        if (out_pending) *out_pending = true;
    }
    return NULL;
}

/* ---------- Lease introspection ---------- */

bool portillia_listener_lease_snapshot(portillia_listener_t *l, portillia_listener_lease_t *out) {
    if (!l || !out) return false;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&l->lease_mu);
    if (!l->lease) {
        pthread_mutex_unlock(&l->lease_mu);
        return false;
    }
    if (l->lease->hostname) out->hostname = portillia_gc_strdup(l->lease->hostname);
    if (l->lease->udp_addr) out->udp_addr = portillia_gc_strdup(l->lease->udp_addr);
    if (l->lease->tcp_addr) out->tcp_addr = portillia_gc_strdup(l->lease->tcp_addr);
    if (l->lease->access_token) out->access_token = portillia_gc_strdup(l->lease->access_token);
    out->expires_at = l->lease->expires_at;
    out->sni_port = l->lease->sni_port;
    pthread_mutex_unlock(&l->lease_mu);
    return true;
}

char *portillia_listener_public_url(portillia_listener_t *l) {
    if (!l) return NULL;
    portillia_listener_lease_t lease = {0};
    if (!portillia_listener_lease_snapshot(l, &lease)) return NULL;
    if (!lease.hostname) return NULL;
    char *url = portillia_gc_alloc(256);
    if (url) {
        snprintf(url, 256, "https://%s", lease.hostname);
    }
    lease_cleanup(&lease);
    return url;
}
