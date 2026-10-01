#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>
#include <portillia/portal/settings.h>
#include <cjson/cJSON.h>
#include <openssl/ssl.h>
#include <errno.h>
#include "portal_bridge.h"
#include <portillia/portal/keyless/bindings.h>

#define MAX_RECORDS 1024
#define READY_LIMIT 8
#define CLAIM_TIMEOUT 10

/* Reverse-session framing markers (protocol v10, portal-tunnel
 * transport/stream_relay.go): the relay writes a single marker byte to
 * activate a claimed session; MARKER_TLS_START is immediately followed by
 * PORTILLIA_BINDING_SIZE bytes of per-connection binding. */
#define MARKER_KEEPALIVE 0x00
#define MARKER_RAW_START 0x01
#define MARKER_TLS_START 0x02

typedef struct relay_session {
    int fd;
    SSL *ssl;
    time_t created_at;
    struct relay_session *next;
} relay_session;

typedef struct relay_stream {
    relay_session *ready_head;
    relay_session *ready_tail;
    int count;
    pthread_mutex_t mu;
    pthread_cond_t cond;
    pthread_t tid;
    bool stop;
} relay_stream;

typedef struct lease_record {
    char *hostname;
    char *identity_key;
    time_t first_seen_at;
    time_t last_seen_at;
    time_t expires_at;
    int64_t bps_limit;
    relay_stream *stream;

    // Privacy
    char *client_ip;
    char *reported_ip;
    char *hostname_hash;

    // Multi-hop
    char *hop_token;
    char *hop_next_overlay_ipv4;
    char *hop_next_token;
} lease_record;

typedef struct lease_registry {
    lease_record *records[MAX_RECORDS];
    int count;
    char *root_hostname;
    pthread_mutex_t mu;
} lease_registry;

typedef struct portillia_server {
    lease_registry *registry;
    int api_port;
    int sni_port;
    portillia_settings *settings;
} portillia_server;

static portillia_server *global_server = NULL;

extern void portillia_proxy_bridge(int client_fd, int target_fd);
extern void portillia_proxy_bridge_ex(int client_fd, int target_fd, int64_t bps_limit);
extern void portillia_proxy_bridge_bound(int client_fd, int target_fd, int64_t bps_limit,
                                         const uint8_t binding[PORTILLIA_BINDING_SIZE]);
extern void portillia_proxy_ssl_bridge_ex(int client_fd, SSL *target_ssl, int64_t bps_limit);
extern void portillia_proxy_ssl_bridge_bound(int client_fd, SSL *target_ssl, int64_t bps_limit,
                                             const uint8_t binding[PORTILLIA_BINDING_SIZE]);

void relay_stream_free(relay_stream *s) {
    if (!s) return;
    
    pthread_mutex_lock(&s->mu);
    s->stop = true;
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->mu);

    pthread_join(s->tid, NULL);

    pthread_mutex_lock(&s->mu);
    relay_session *curr = s->ready_head;
    while (curr) {
        relay_session *next = curr->next;
        if (curr->ssl) {
            SSL_shutdown(curr->ssl);
            SSL_free(curr->ssl);
        }
        close(curr->fd);
        free(curr);
        curr = next;
    }
    pthread_mutex_unlock(&s->mu);
    pthread_mutex_destroy(&s->mu);
    pthread_cond_destroy(&s->cond);
    free(s);
}

void *stream_keepalive_thread(void *arg) {
    relay_stream *s = (relay_stream *)arg;
    uint8_t marker = 0x00; // MarkerKeepalive
    while (1) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 15;

        pthread_mutex_lock(&s->mu);
        while (!s->stop) {
            int rc = pthread_cond_timedwait(&s->cond, &s->mu, &ts);
            if (rc == ETIMEDOUT) break;
        }

        if (s->stop) {
            pthread_mutex_unlock(&s->mu);
            break;
        }

        /* Periodic reclaim of expired, unused keyless bindings
         * (bindings.go SweepExpired). */
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        portillia_bindings_sweep_expired(portillia_bindings_shared(), now);

        relay_session *curr = s->ready_head;
        while (curr) {
            if (curr->ssl) {
                if (SSL_write(curr->ssl, &marker, 1) != 1) {
                    // Connection broken
                }
            } else {
                if (write(curr->fd, &marker, 1) != 1) {
                    // Connection broken
                }
            }
            curr = curr->next;
        }
        pthread_mutex_unlock(&s->mu);
    }
    return NULL;
}

relay_stream *relay_stream_new() {
    relay_stream *s = calloc(1, sizeof(relay_stream));
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cond, NULL);
    s->stop = false;

    pthread_create(&s->tid, NULL, stream_keepalive_thread, s);

    return s;
}

int relay_stream_offer(relay_stream *s, int fd, SSL *ssl) {
    pthread_mutex_lock(&s->mu);
    if (s->count >= READY_LIMIT) {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(fd);
        pthread_mutex_unlock(&s->mu);
        return -1;
    }
    relay_session *sess = calloc(1, sizeof(relay_session));
    sess->fd = fd;
    sess->ssl = ssl;
    sess->created_at = time(NULL);
    if (s->ready_tail) {
        s->ready_tail->next = sess;
        s->ready_tail = sess;
    } else {
        s->ready_head = s->ready_tail = sess;
    }
    s->count++;
    int ready_count = s->count;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->mu);
    return ready_count;
}

/* Claim activates the next ready session for tenant TLS (stream_relay.go
 * Claim): mints a fresh binding for the lease, writes MARKER_TLS_START
 * followed by the 16-byte binding, and hands the binding back so the proxy
 * path can pin it to the first relay-observed ClientHello. */
bool relay_stream_claim(relay_stream *s, const char *lease_id, int *out_fd, SSL **out_ssl,
                        uint8_t binding_out[PORTILLIA_BINDING_SIZE]) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += CLAIM_TIMEOUT;

    pthread_mutex_lock(&s->mu);
    while (s->count == 0) {
        if (pthread_cond_timedwait(&s->cond, &s->mu, &ts) != 0) {
            pthread_mutex_unlock(&s->mu);
            return false;
        }
    }
    relay_session *sess = s->ready_head;
    s->ready_head = sess->next;
    if (!s->ready_head) s->ready_tail = NULL;
    s->count--;
    int fd = sess->fd;
    SSL *ssl = sess->ssl;
    free(sess);
    pthread_mutex_unlock(&s->mu);

    /* Mint the per-connection binding up front; discard it if the
     * activation frame never reaches a live stream. */
    uint8_t binding[PORTILLIA_BINDING_SIZE];
    portillia_bindings_issue(portillia_bindings_shared(), lease_id, NULL, 0, binding);

    /* Activation frame: 0x02 || 16-byte binding (stream_relay.go
     * activateWithMarker). Write marker and binding as one frame. */
    uint8_t frame[1 + PORTILLIA_BINDING_SIZE];
    frame[0] = MARKER_TLS_START;
    memcpy(frame + 1, binding, PORTILLIA_BINDING_SIZE);
    int sent = ssl ? SSL_write(ssl, frame, sizeof(frame)) : (int)write(fd, frame, sizeof(frame));
    if (sent != (int)sizeof(frame)) {
        portillia_bindings_discard(portillia_bindings_shared(), binding);
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(fd);
        return false;
    }

    if (out_fd) *out_fd = fd;
    if (out_ssl) *out_ssl = ssl;
    if (binding_out) memcpy(binding_out, binding, PORTILLIA_BINDING_SIZE);
    return true;
}

lease_registry* lease_registry_new(const char *root_hostname) {
    lease_registry *r = calloc(1, sizeof(lease_registry));
    r->root_hostname = strdup(root_hostname);
    pthread_mutex_init(&r->mu, NULL);
    return r;
}

bool lease_registry_is_allowed(lease_registry *r, const char *identity_key) {
    portillia_settings *s = global_server->settings;
    if (!s) return true;

    // Check Ban List
    for (int i = 0; i < s->banned_count; i++) {
        if (strcmp(s->banned_identities[i], identity_key) == 0) return false;
    }

    // Check Approval Mode
    if (strcmp(s->approval_mode, "manual") == 0) {
        for (int i = 0; i < s->approved_count; i++) {
            if (strcmp(s->approved_identities[i], identity_key) == 0) return true;
        }
        return false;
    }

    return true;
}

void lease_registry_register(lease_registry *r, const char *hostname, const char *identity_key, int64_t bps_limit,
                               const char *client_ip, const char *reported_ip,
                               const char *hostname_hash) {
    if (!lease_registry_is_allowed(r, identity_key)) return;
    pthread_mutex_lock(&r->mu);
    time_t now = time(NULL);
    for (int i = 0; i < r->count; i++) {
        if (r->records[i]->hostname && strcmp(r->records[i]->hostname, hostname) == 0) {
            r->records[i]->expires_at = now + 300;
            r->records[i]->last_seen_at = now;
            r->records[i]->bps_limit = bps_limit;
            if (client_ip) { free(r->records[i]->client_ip); r->records[i]->client_ip = strdup(client_ip); }
            if (reported_ip) { free(r->records[i]->reported_ip); r->records[i]->reported_ip = strdup(reported_ip); }
            if (hostname_hash) { free(r->records[i]->hostname_hash); r->records[i]->hostname_hash = strdup(hostname_hash); }
            pthread_mutex_unlock(&r->mu);
            return;
        }
    }
    if (r->count < MAX_RECORDS) {
        lease_record *rec = calloc(1, sizeof(lease_record));
        rec->hostname = hostname ? strdup(hostname) : NULL;
        rec->identity_key = strdup(identity_key);
        rec->first_seen_at = now;
        rec->last_seen_at = now;
        rec->expires_at = now + 300;
        rec->bps_limit = bps_limit;
        rec->stream = relay_stream_new();
        if (client_ip) rec->client_ip = strdup(client_ip);
        if (reported_ip) rec->reported_ip = strdup(reported_ip);
        if (hostname_hash) rec->hostname_hash = strdup(hostname_hash);
        r->records[r->count++] = rec;
    }
    pthread_mutex_unlock(&r->mu);
}

void portillia_registry_register_hop(const char *hop_token, const char *next_ipv4, const char *next_token, const char *identity_key) {
    if (!global_server || !global_server->registry) return;
    lease_registry *r = global_server->registry;
    pthread_mutex_lock(&r->mu);
    time_t now = time(NULL);
    for (int i = 0; i < r->count; i++) {
        if (r->records[i]->hop_token && strcmp(r->records[i]->hop_token, hop_token) == 0) {
            r->records[i]->expires_at = now + 300;
            pthread_mutex_unlock(&r->mu);
            return;
        }
    }
    if (r->count < MAX_RECORDS) {
        lease_record *rec = calloc(1, sizeof(lease_record));
        rec->hop_token = strdup(hop_token);
        rec->hop_next_overlay_ipv4 = strdup(next_ipv4);
        rec->hop_next_token = strdup(next_token);
        rec->identity_key = strdup(identity_key);
        rec->expires_at = now + 300;
        r->records[r->count++] = rec;
    }
    pthread_mutex_unlock(&r->mu);
}

void portillia_registry_update_bps(const char *identity_key, int64_t bps) {
    if (!global_server) return;
    lease_registry *r = global_server->registry;
    pthread_mutex_lock(&r->mu);
    for (int i = 0; i < r->count; i++) {
        if (r->records[i]->identity_key && strcmp(r->records[i]->identity_key, identity_key) == 0) {
            r->records[i]->bps_limit = bps;
            break;
        }
    }
    pthread_mutex_unlock(&r->mu);
}

lease_record *lease_registry_lookup(lease_registry *r, const char *hostname) {
    pthread_mutex_lock(&r->mu);
    time_t now = time(NULL);
    // Exact match first
    for (int i = 0; i < r->count; i++) {
        if (r->records[i]->hostname && strcmp(r->records[i]->hostname, hostname) == 0) {
            if (r->records[i]->expires_at > now) {
                pthread_mutex_unlock(&r->mu);
                return r->records[i];
            }
        }
    }
    // Hostname hash match
    char *computed_hash = HostnameHashJSON(hostname);
    if (computed_hash) {
        for (int i = 0; i < r->count; i++) {
            if (r->records[i]->hostname_hash && strcmp(r->records[i]->hostname_hash, computed_hash) == 0) {
                if (r->records[i]->expires_at > now) {
                    FreeCString(computed_hash);
                    pthread_mutex_unlock(&r->mu);
                    return r->records[i];
                }
            }
        }
        FreeCString(computed_hash);
    }
    // Pattern match
    for (int i = 0; i < r->count; i++) {
        if (r->records[i]->hostname && hostname_matches(r->records[i]->hostname, hostname)) {
            if (r->records[i]->expires_at > now) {
                pthread_mutex_unlock(&r->mu);
                return r->records[i];
            }
        }
    }
    pthread_mutex_unlock(&r->mu);
    return NULL;
}

lease_record *lease_registry_lookup_hop(lease_registry *r, const char *token) {
    pthread_mutex_lock(&r->mu);
    time_t now = time(NULL);
    for (int i = 0; i < r->count; i++) {
        if (r->records[i]->hop_token && strcmp(r->records[i]->hop_token, token) == 0) {
            if (r->records[i]->expires_at > now) {
                pthread_mutex_unlock(&r->mu);
                return r->records[i];
            }
        }
    }
    pthread_mutex_unlock(&r->mu);
    return NULL;
}

void *lease_janitor_thread(void *arg) {
    lease_registry *r = (lease_registry *)arg;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&r->mu);
        time_t now = time(NULL);
        for (int i = 0; i < r->count; i++) {
            if (r->records[i]->expires_at <= now) {
                LOG_INFO("Record expired, cleaning up");
                lease_record *rec = r->records[i];
                if (rec->stream) relay_stream_free(rec->stream);
                if (rec->hostname) free(rec->hostname);
                if (rec->identity_key) free(rec->identity_key);
                if (rec->client_ip) free(rec->client_ip);
                if (rec->reported_ip) free(rec->reported_ip);
                if (rec->hostname_hash) free(rec->hostname_hash);
                if (rec->hop_token) free(rec->hop_token);
                if (rec->hop_next_overlay_ipv4) free(rec->hop_next_overlay_ipv4);
                if (rec->hop_next_token) free(rec->hop_next_token);
                free(rec);
                r->records[i] = r->records[--r->count];
                i--;
            }
        }
        pthread_mutex_unlock(&r->mu);
    }
    return NULL;
}

void portillia_server_setup(const char *root_hostname, int api_port, int sni_port, portillia_settings *s) {
    global_server = calloc(1, sizeof(portillia_server));
    global_server->registry = lease_registry_new(root_hostname);
    global_server->api_port = api_port;
    global_server->sni_port = sni_port;
    global_server->settings = s;

    pthread_t janitor_tid;
    pthread_create(&janitor_tid, NULL, lease_janitor_thread, global_server->registry);
    pthread_detach(janitor_tid);
}

static int dial_next_hop(const char *ipv4, const char *token) {
    return HopMuxOpenStreamFD(ipv4, token);
}

void portillia_server_handle_connect(const char *hostname, int client_fd) {
    if (!global_server) { LOG_WARN("server not ready, closing client"); close(client_fd); return; }
    
    LOG_INFO("sni_connect hostname=%s root=%s", hostname, global_server->registry->root_hostname);
    if (strcmp(hostname, global_server->registry->root_hostname) == 0) {
        int target_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in target = { .sin_family = AF_INET, .sin_port = htons(global_server->api_port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        if (connect(target_fd, (struct sockaddr *)&target, sizeof(target)) == 0) {
            LOG_INFO("sni_connect root forward to api_port=%d", global_server->api_port);
            /* The API server now terminates TLS itself; replay the client's
             * TLS bytes verbatim to it via zero-copy splice instead of pumping
             * through OpenSSL twice. */
            portillia_proxy_bridge_ex(client_fd, target_fd, 0);
        } else {
            LOG_WARN("sni_connect root connect to api_port=%d failed errno=%d", global_server->api_port, errno);
            close(target_fd);
            close(client_fd);
        }
        return;
    }

    lease_record *rec = lease_registry_lookup(global_server->registry, hostname);
    if (rec) {
        LOG_INFO("sni_connect lease found hostname=%s bps=%ld", hostname, (long)rec->bps_limit);
        if (rec->hop_next_overlay_ipv4) {
            int next_fd = dial_next_hop(rec->hop_next_overlay_ipv4, rec->hop_next_token);
            if (next_fd >= 0) {
                LOG_INFO("sni_connect hop opened fd=%d", next_fd);
                portillia_proxy_bridge_ex(client_fd, next_fd, rec->bps_limit);
            } else {
                LOG_WARN("sni_connect hop open failed hostname=%s next=%s", hostname, rec->hop_next_overlay_ipv4);
                close(client_fd);
            }
        } else {
            /* Tenant TLS termination decision point (portal-tunnel
             * keyless/client.go): tenant TLS never terminates on the relay.
             * Claim mints the per-connection binding (server.go
             * bridgeLeaseConn: Issue with the hello span already observed)
             * and writes 0x02 || binding on the reverse session; the browser's
             * TLS bytes are then spliced verbatim (proxy.c hello capture pins
             * the binding to the first relay-observed ClientHello, equivalent
             * to bindings.go FixHelloOnWrite) to the SDK-side keyless TLS
             * terminator, whose CertificateVerify is signed through the
             * relay's transcript-bound /v1/sign. The relay-side cwist TLS
             * only peeks SNI for routing; the bytes forwarded to the tenant
             * are identical to what stream_relay.go forwards, so no relay-side
             * t13server port is needed. */
            uint8_t binding[PORTILLIA_BINDING_SIZE];
            int sdk_fd = -1;
            SSL *sdk_ssl = NULL;
            if (relay_stream_claim(rec->stream, rec->identity_key, &sdk_fd, &sdk_ssl, binding)) {
                LOG_INFO("sni_connect sdk claimed fd=%d ssl=%p", sdk_fd, (void*)sdk_ssl);
                if (sdk_ssl) {
                    portillia_proxy_ssl_bridge_bound(client_fd, sdk_ssl, rec->bps_limit, binding);
                } else {
                    portillia_proxy_bridge_bound(client_fd, sdk_fd, rec->bps_limit, binding);
                }
            } else {
                LOG_WARN("sni_connect sdk claim failed hostname=%s", hostname);
                close(client_fd);
            }
        }
    } else {
        LOG_WARN("sni_connect no lease for hostname=%s", hostname);
        close(client_fd);
    }
}

void portillia_server_handle_hop_stream(int hop_fd, const char *token) {
    LOG_INFO("hop_stream token=%.8s... fd=%d", token, hop_fd);
    lease_record *rec = lease_registry_lookup_hop(global_server->registry, token);
    if (rec) {
        if (rec->hop_next_overlay_ipv4) {
             int next_fd = dial_next_hop(rec->hop_next_overlay_ipv4, rec->hop_next_token);
             if (next_fd >= 0) {
                 LOG_INFO("hop_stream next hop fd=%d", next_fd);
                 portillia_proxy_bridge_ex(hop_fd, next_fd, rec->bps_limit);
             } else {
                 LOG_WARN("hop_stream next hop failed token=%.8s... next=%s", token, rec->hop_next_overlay_ipv4);
                 close(hop_fd);
             }
        } else {
             uint8_t binding[PORTILLIA_BINDING_SIZE];
             int sdk_fd = -1;
             SSL *sdk_ssl = NULL;
             if (relay_stream_claim(rec->stream, rec->identity_key, &sdk_fd, &sdk_ssl, binding)) {
                 LOG_INFO("hop_stream sdk claimed fd=%d ssl=%p", sdk_fd, (void*)sdk_ssl);
                 if (sdk_ssl) {
                     portillia_proxy_ssl_bridge_bound(hop_fd, sdk_ssl, rec->bps_limit, binding);
                 } else {
                     portillia_proxy_bridge_bound(hop_fd, sdk_fd, rec->bps_limit, binding);
                 }
             } else {
                 LOG_WARN("hop_stream sdk claim failed token=%.8s...", token);
                 close(hop_fd);
             }
        }
    } else {
        LOG_WARN("hop_stream no lease for token=%.8s...", token);
        close(hop_fd);
    }
}

void portillia_server_handle_hop(int hop_fd) {
    uint32_t net_len;
    if (read(hop_fd, &net_len, 4) != 4) { close(hop_fd); return; }
    uint32_t len = ntohl(net_len);
    if (len == 0 || len > 256) { close(hop_fd); return; }
    char token[257];
    if (read(hop_fd, token, len) != (ssize_t)len) { close(hop_fd); return; }
    token[len] = '\0';
    portillia_server_handle_hop_stream(hop_fd, token);
}

int portillia_registry_offer_conn(const char *hostname, int sdk_fd) {
    if (!global_server) { close(sdk_fd); return -1; }
    lease_record *rec = lease_registry_lookup(global_server->registry, hostname);
    if (rec) {
        rec->last_seen_at = time(NULL);
        return relay_stream_offer(rec->stream, sdk_fd, NULL);
    } else {
        close(sdk_fd);
    }
    return -1;
}

int portillia_registry_offer_ssl_conn(const char *hostname, int sdk_fd, SSL *sdk_ssl) {
    if (!global_server) {
        if (sdk_ssl) { SSL_shutdown(sdk_ssl); SSL_free(sdk_ssl); }
        close(sdk_fd);
        return -1;
    }
    lease_record *rec = lease_registry_lookup(global_server->registry, hostname);
    if (rec) {
        rec->last_seen_at = time(NULL);
        return relay_stream_offer(rec->stream, sdk_fd, sdk_ssl);
    } else {
        if (sdk_ssl) { SSL_shutdown(sdk_ssl); SSL_free(sdk_ssl); }
        close(sdk_fd);
    }
    return -1;
}

bool portillia_registry_tunnel_status(const char *hostname, char *resolved_hostname, size_t resolved_hostname_len, bool *service_alive) {
    if (resolved_hostname && resolved_hostname_len > 0) {
        resolved_hostname[0] = '\0';
    }
    if (service_alive) {
        *service_alive = false;
    }
    if (!global_server || !hostname) return false;

    lease_record *rec = lease_registry_lookup(global_server->registry, hostname);
    if (!rec || !rec->hostname) return false;

    if (resolved_hostname && resolved_hostname_len > 0) {
        snprintf(resolved_hostname, resolved_hostname_len, "%s", rec->hostname);
    }

    if (service_alive && rec->stream) {
        pthread_mutex_lock(&rec->stream->mu);
        *service_alive = rec->stream->count > 0;
        pthread_mutex_unlock(&rec->stream->mu);
    }

    return true;
}

void portillia_registry_register(const char *hostname, const char *identity_key, int64_t bps_limit) {
    if (!global_server) return;
    lease_registry_register(global_server->registry, hostname, identity_key, bps_limit,
                            NULL, NULL, NULL);
}

void portillia_registry_register_ex(const char *hostname, const char *identity_key, int64_t bps_limit,
                                    const char *client_ip, const char *reported_ip,
                                    const char *hostname_hash) {
    if (!global_server) return;
    lease_registry_register(global_server->registry, hostname, identity_key, bps_limit,
                            client_ip, reported_ip, hostname_hash);
}

char* portillia_registry_to_json() {
    if (!global_server) return strdup("[]");
    lease_registry *r = global_server->registry;
    pthread_mutex_lock(&r->mu);
    
    cJSON *root = cJSON_CreateArray();
    time_t now = time(NULL);
    for (int i = 0; i < r->count; i++) {
        lease_record *rec = r->records[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "hostname", rec->hostname ? rec->hostname : "");
        cJSON_AddStringToObject(item, "identity_key", rec->identity_key);
        cJSON_AddStringToObject(item, "client_ip", rec->client_ip ? rec->client_ip : "");
        cJSON_AddStringToObject(item, "reported_ip", rec->reported_ip ? rec->reported_ip : "");
        cJSON_AddStringToObject(item, "hostname_hash", rec->hostname_hash ? rec->hostname_hash : "");
        cJSON_AddNumberToObject(item, "expires_in", (double)(rec->expires_at - now));
        cJSON_AddNumberToObject(item, "ready", (double)(rec->stream ? rec->stream->count : 0));
        cJSON_AddNumberToObject(item, "bps_limit", (double)rec->bps_limit);
        cJSON_AddItemToArray(root, item);
    }
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    pthread_mutex_unlock(&r->mu);
    return json;
}

portillia_settings* portillia_server_get_settings() {
    return global_server ? global_server->settings : NULL;
}

const char* portillia_server_root_hostname() {
    if (!global_server || !global_server->registry) return NULL;
    return global_server->registry->root_hostname;
}

int portillia_server_sni_port() {
    if (!global_server) return 443;
    return global_server->sni_port;
}
