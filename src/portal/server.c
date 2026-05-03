#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>
#include <portillia/portal/settings.h>
#include <cjson/cJSON.h>

#define MAX_RECORDS 1024
#define READY_LIMIT 8
#define CLAIM_TIMEOUT 10

typedef struct relay_session {
    int fd;
    time_t created_at;
    struct relay_session *next;
} relay_session;

typedef struct relay_stream {
    relay_session *ready_head;
    relay_session *ready_tail;
    int count;
    pthread_mutex_t mu;
    pthread_cond_t cond;
} relay_stream;

typedef struct lease_record {
    char *hostname;
    char *identity_key;
    time_t first_seen_at;
    time_t last_seen_at;
    time_t expires_at;
    int64_t bps_limit;
    relay_stream *stream;

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

void relay_stream_free(relay_stream *s) {
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    relay_session *curr = s->ready_head;
    while (curr) {
        relay_session *next = curr->next;
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
        sleep(15);
        pthread_mutex_lock(&s->mu);
        relay_session *curr = s->ready_head;
        while (curr) {
            if (write(curr->fd, &marker, 1) != 1) {
                // Connection broken
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

    pthread_t tid;
    pthread_create(&tid, NULL, stream_keepalive_thread, s);
    pthread_detach(tid);

    return s;
}

void relay_stream_offer(relay_stream *s, int fd) {
    pthread_mutex_lock(&s->mu);
    if (s->count >= READY_LIMIT) {
        close(fd);
        pthread_mutex_unlock(&s->mu);
        return;
    }
    relay_session *sess = calloc(1, sizeof(relay_session));
    sess->fd = fd;
    sess->created_at = time(NULL);
    if (s->ready_tail) {
        s->ready_tail->next = sess;
        s->ready_tail = sess;
    } else {
        s->ready_head = s->ready_tail = sess;
    }
    s->count++;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->mu);
}

int relay_stream_claim(relay_stream *s) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += CLAIM_TIMEOUT;

    pthread_mutex_lock(&s->mu);
    while (s->count == 0) {
        if (pthread_cond_timedwait(&s->cond, &s->mu, &ts) != 0) {
            pthread_mutex_unlock(&s->mu);
            return -1;
        }
    }
    relay_session *sess = s->ready_head;
    s->ready_head = sess->next;
    if (!s->ready_head) s->ready_tail = NULL;
    s->count--;
    int fd = sess->fd;
    free(sess);
    pthread_mutex_unlock(&s->mu);

    // Send Marker (MarkerTLSStart = 0x02 in Go)
    uint8_t marker = 0x02; 
    if (write(fd, &marker, 1) != 1) {
        close(fd);
        return -1;
    }
    return fd;
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

void lease_registry_register(lease_registry *r, const char *hostname, const char *identity_key, int64_t bps_limit) {
    if (!lease_registry_is_allowed(r, identity_key)) return;
    pthread_mutex_lock(&r->mu);
    time_t now = time(NULL);
    for (int i = 0; i < r->count; i++) {
        if (r->records[i]->hostname && strcmp(r->records[i]->hostname, hostname) == 0) {
            r->records[i]->expires_at = now + 30;
            r->records[i]->last_seen_at = now;
            r->records[i]->bps_limit = bps_limit;
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
        rec->expires_at = now + 30;
        rec->bps_limit = bps_limit;
        rec->stream = relay_stream_new();
        r->records[r->count++] = rec;
    }
    pthread_mutex_unlock(&r->mu);
}

void portillia_registry_register_hop(lease_registry *r, const char *hop_token, const char *next_ipv4, const char *next_token, const char *identity_key) {
    pthread_mutex_lock(&r->mu);
    time_t now = time(NULL);
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
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    inet_pton(AF_INET, ipv4, &addr.sin_addr);
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    uint32_t len = htonl(strlen(token));
    write(fd, &len, 4);
    write(fd, token, strlen(token));
    
    return fd;
}

void portillia_server_handle_connect(const char *hostname, int client_fd) {
    if (!global_server) { close(client_fd); return; }
    
    if (strcmp(hostname, global_server->registry->root_hostname) == 0) {
        int target_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in target = { .sin_family = AF_INET, .sin_port = htons(global_server->api_port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        if (connect(target_fd, (struct sockaddr *)&target, sizeof(target)) == 0) {
            extern void portillia_proxy_bridge(int client_fd, int target_fd);
            portillia_proxy_bridge(client_fd, target_fd);
        } else {
            close(target_fd);
            close(client_fd);
        }
        return;
    }

    lease_record *rec = lease_registry_lookup(global_server->registry, hostname);
    if (rec) {
        if (rec->hop_next_overlay_ipv4) {
            int next_fd = dial_next_hop(rec->hop_next_overlay_ipv4, rec->hop_next_token);
            if (next_fd >= 0) {
                extern void portillia_proxy_bridge_ex(int client_fd, int target_fd, int64_t bps_limit);
                portillia_proxy_bridge_ex(client_fd, next_fd, rec->bps_limit);
            } else {
                close(client_fd);
            }
        } else {
            int sdk_fd = relay_stream_claim(rec->stream);
            if (sdk_fd >= 0) {
                extern void portillia_proxy_bridge_ex(int client_fd, int target_fd, int64_t bps_limit);
                portillia_proxy_bridge_ex(client_fd, sdk_fd, rec->bps_limit);
            } else {
                close(client_fd);
            }
        }
    } else {
        close(client_fd);
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

    lease_record *rec = lease_registry_lookup_hop(global_server->registry, token);
    if (rec) {
        if (rec->hop_next_overlay_ipv4) {
             int next_fd = dial_next_hop(rec->hop_next_overlay_ipv4, rec->hop_next_token);
             if (next_fd >= 0) {
                 extern void portillia_proxy_bridge_ex(int client_fd, int target_fd, int64_t bps_limit);
                 portillia_proxy_bridge_ex(hop_fd, next_fd, rec->bps_limit);
             } else {
                 close(hop_fd);
             }
        } else {
             int sdk_fd = relay_stream_claim(rec->stream);
             if (sdk_fd >= 0) {
                 extern void portillia_proxy_bridge_ex(int client_fd, int target_fd, int64_t bps_limit);
                 portillia_proxy_bridge_ex(hop_fd, sdk_fd, rec->bps_limit);
             } else {
                 close(hop_fd);
             }
        }
    } else {
        close(hop_fd);
    }
}

void portillia_registry_offer_conn(const char *hostname, int sdk_fd) {
    if (!global_server) { close(sdk_fd); return; }
    lease_record *rec = lease_registry_lookup(global_server->registry, hostname);
    if (rec) {
        rec->last_seen_at = time(NULL);
        relay_stream_offer(rec->stream, sdk_fd);
    } else {
        close(sdk_fd);
    }
}

void portillia_registry_register(const char *hostname, const char *identity_key, int64_t bps_limit) {
    if (!global_server) return;
    lease_registry_register(global_server->registry, hostname, identity_key, bps_limit);
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