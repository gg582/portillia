/** @file expose.c
 * @brief SDK exposure logic — C port of portal-tunnel/sdk/expose.go.
 *
 * All heap allocations use the global EpochGC.
 */

#include <portillia/sdk/expose.h>
#include <portillia/sdk/listener.h>
#include <portillia/sdk/http_runtime.h>
#include <portillia/discovery/relay_set.h>
#include <portillia/utils/log.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <cjson/cJSON.h>
#include <math.h>

/* ---------- Internal types ---------- */

typedef struct portillia_conn_channel {
    portillia_net_conn_t **items;
    size_t cap;
    size_t count;
    size_t head;
    size_t tail;
    pthread_mutex_t mu;
    pthread_cond_t cond;
    bool closed;
} portillia_conn_channel_t;

typedef struct {
    portillia_listener_t *listener;
    portillia_exposure_t *exposure;
} listener_accept_arg_t;

/* ---------- Forward declarations ---------- */
static int reconcile_relay_listeners(portillia_exposure_t *e, bool fail_on_error);
static void *discovery_loop_thread(void *arg);

/* ---------- Internal helpers ---------- */

static int max_int(int a, int b) { return a > b ? a : b; }

static bool strings_equal(const char *a, const char *b) {
    if (a == b) return true;
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

static bool string_in_list(const char *s, char **list, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (strings_equal(s, list[i])) return true;
    }
    return false;
}

static int listener_index_by_url(portillia_exposure_t *e, const char *url) {
    for (size_t i = 0; i < e->listener_count; i++) {
        if (strings_equal(url, e->listener_urls[i])) return (int)i;
    }
    return -1;
}

static void exposure_add_listener(portillia_exposure_t *e, const char *url, portillia_listener_t *listener) {
    if (e->listener_count >= e->listener_cap) {
        size_t new_cap = e->listener_cap == 0 ? 4 : e->listener_cap * 2;
        char **new_urls = (char **)portillia_gc_alloc(sizeof(char *) * new_cap);
        portillia_listener_t **new_listeners = (portillia_listener_t **)portillia_gc_alloc(sizeof(portillia_listener_t *) * new_cap);
        if (!new_urls || !new_listeners) {
            if (new_urls) portillia_gc_free_later(new_urls);
            if (new_listeners) portillia_gc_free_later(new_listeners);
            return;
        }
        for (size_t i = 0; i < e->listener_count; i++) {
            new_urls[i] = e->listener_urls[i];
            new_listeners[i] = e->listeners[i];
        }
        if (e->listener_urls) portillia_gc_free_later(e->listener_urls);
        if (e->listeners) portillia_gc_free_later(e->listeners);
        e->listener_urls = new_urls;
        e->listeners = new_listeners;
        e->listener_cap = new_cap;
    }
    e->listener_urls[e->listener_count] = portillia_gc_strdup(url);
    e->listeners[e->listener_count] = listener;
    e->listener_count++;
}

static void exposure_remove_listener_at(portillia_exposure_t *e, size_t idx) {
    if (idx >= e->listener_count) return;
    if (e->listener_accept_tids) {
        /* Close listener first so accept thread exits, then join. */
        if (e->listeners[idx]) portillia_listener_close(e->listeners[idx]);
        pthread_join(e->listener_accept_tids[idx], NULL);
    } else {
        if (e->listeners[idx]) portillia_listener_close(e->listeners[idx]);
    }
    if (e->listener_urls[idx]) portillia_gc_free_later(e->listener_urls[idx]);
    for (size_t i = idx; i + 1 < e->listener_count; i++) {
        e->listener_urls[i] = e->listener_urls[i + 1];
        e->listeners[i] = e->listeners[i + 1];
        if (e->listener_accept_tids) {
            e->listener_accept_tids[i] = e->listener_accept_tids[i + 1];
        }
    }
    e->listener_count--;
}

static char **string_list_copy(char **src, size_t count) {
    if (count == 0 || !src) return NULL;
    char **dst = (char **)portillia_gc_alloc(sizeof(char *) * count);
    if (!dst) return NULL;
    for (size_t i = 0; i < count; i++) {
        dst[i] = src[i] ? portillia_gc_strdup(src[i]) : NULL;
    }
    return dst;
}

static void string_list_free(char **list, size_t count) {
    if (!list) return;
    for (size_t i = 0; i < count; i++) {
        if (list[i]) portillia_gc_free_later(list[i]);
    }
    portillia_gc_free_later(list);
}

static bool exposure_done(const portillia_exposure_t *e) {
    return atomic_load(&e->cancelled);
}

static void exposure_cancel(portillia_exposure_t *e) {
    pthread_mutex_lock(&e->cancel_mu);
    atomic_store(&e->cancelled, true);
    e->done = true;
    pthread_cond_broadcast(&e->cancel_cond);
    pthread_mutex_unlock(&e->cancel_mu);
}

/* ---------- Channel helpers ---------- */

static portillia_conn_channel_t *channel_new(size_t cap) {
    portillia_conn_channel_t *ch = (portillia_conn_channel_t *)portillia_gc_alloc(sizeof(*ch));
    if (!ch) return NULL;
    memset(ch, 0, sizeof(*ch));
    ch->items = (portillia_net_conn_t **)portillia_gc_alloc(sizeof(portillia_net_conn_t *) * cap);
    if (!ch->items) {
        portillia_gc_free_later(ch);
        return NULL;
    }
    ch->cap = cap;
    pthread_mutex_init(&ch->mu, NULL);
    pthread_cond_init(&ch->cond, NULL);
    return ch;
}

static void channel_close(portillia_conn_channel_t *ch) {
    if (!ch) return;
    pthread_mutex_lock(&ch->mu);
    ch->closed = true;
    pthread_cond_broadcast(&ch->cond);
    pthread_mutex_unlock(&ch->mu);
}

static void channel_free(portillia_conn_channel_t *ch) {
    if (!ch) return;
    channel_close(ch);
    pthread_mutex_lock(&ch->mu);
    while (ch->count > 0) {
        portillia_net_conn_t *conn = ch->items[ch->head];
        ch->head = (ch->head + 1) % ch->cap;
        ch->count--;
        if (conn) {
            portillia_net_conn_cleanup(conn);
            portillia_gc_free_later(conn);
        }
    }
    pthread_mutex_unlock(&ch->mu);
    pthread_mutex_destroy(&ch->mu);
    pthread_cond_destroy(&ch->cond);
    if (ch->items) portillia_gc_free_later(ch->items);
    portillia_gc_free_later(ch);
}

static bool channel_push(portillia_conn_channel_t *ch, portillia_net_conn_t *conn) {
    if (!ch || !conn) return false;
    pthread_mutex_lock(&ch->mu);
    if (ch->closed || ch->count >= ch->cap) {
        pthread_mutex_unlock(&ch->mu);
        return false;
    }
    ch->items[ch->tail] = conn;
    ch->tail = (ch->tail + 1) % ch->cap;
    ch->count++;
    pthread_cond_signal(&ch->cond);
    pthread_mutex_unlock(&ch->mu);
    return true;
}

static portillia_net_conn_t *channel_pop(portillia_conn_channel_t *ch, bool *out_closed) {
    if (!ch) {
        if (out_closed) *out_closed = true;
        return NULL;
    }
    pthread_mutex_lock(&ch->mu);
    while (ch->count == 0 && !ch->closed) {
        pthread_cond_wait(&ch->cond, &ch->mu);
    }
    if (ch->closed) {
        pthread_mutex_unlock(&ch->mu);
        if (out_closed) *out_closed = true;
        return NULL;
    }
    portillia_net_conn_t *conn = ch->items[ch->head];
    ch->head = (ch->head + 1) % ch->cap;
    ch->count--;
    pthread_mutex_unlock(&ch->mu);
    if (out_closed) *out_closed = false;
    return conn;
}

/* ---------- Accept thread ---------- */

static void *listener_accept_thread(void *arg) {
    listener_accept_arg_t *a = (listener_accept_arg_t *)arg;
    portillia_listener_t *l = a->listener;
    portillia_exposure_t *e = a->exposure;
    portillia_gc_free_later(a);
    while (!exposure_done(e) && !l->cancelled) {
        portillia_net_conn_t *conn = portillia_listener_accept(l);
        if (!conn) {
            if (l->cancelled) break;
            sleep(1);
            continue;
        }
        if (!channel_push((portillia_conn_channel_t *)e->accepted, conn)) {
            portillia_net_conn_close(conn);
        }
    }
    return NULL;
}

static int start_listener_accept_thread(portillia_exposure_t *e, portillia_listener_t *l, pthread_t *out_tid) {
    listener_accept_arg_t *arg = (listener_accept_arg_t *)portillia_gc_alloc(sizeof(*arg));
    if (!arg) return -1;
    arg->listener = l;
    arg->exposure = e;
    if (pthread_create(out_tid, NULL, listener_accept_thread, arg) != 0) {
        portillia_gc_free_later(arg);
        return -1;
    }
    return 0;
}

/* ---------- Net address ---------- */

static portillia_net_addr_t make_exposure_addr(const char *addr) {
    portillia_net_addr_t a;
    memset(&a, 0, sizeof(a));
    strncpy(a.network, "portal", sizeof(a.network) - 1);
    if (addr && addr[0]) {
        snprintf(a.address, sizeof(a.address), "portal:%s", addr);
    } else {
        strncpy(a.address, "portal:exposure", sizeof(a.address) - 1);
    }
    return a;
}

/* ---------- Exposure public API ---------- */

portillia_exposure_t *portillia_expose(const portillia_expose_config_t *cfg) {
    if (!cfg) {
        errno = EINVAL;
        return NULL;
    }

    /* Initialize global GC if not already done. */
    portillia_gc_init_global();

    portillia_exposure_t *e = PORTILLIA_GC_NEW_ZERO(portillia_exposure_t);
    if (!e) {
        errno = ENOMEM;
        return NULL;
    }

    atomic_init(&e->cancelled, false);
    pthread_mutex_init(&e->cancel_mu, NULL);
    pthread_cond_init(&e->cancel_cond, NULL);
    pthread_rwlock_init(&e->listener_mu, NULL);
    e->close_once = (pthread_once_t)PTHREAD_ONCE_INIT;
    atomic_init(&e->conn_seq, 0);

    portillia_identity_init(&e->identity);
    if (cfg->identity_path && cfg->identity_path[0]) {
        FILE *f = fopen(cfg->identity_path, "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (fsize > 0 && fsize < 65536) {
                char *buf = (char *)malloc(fsize + 1);
                if (buf && fread(buf, 1, fsize, f) == (size_t)fsize) {
                    buf[fsize] = '\0';
                    cJSON *root = cJSON_Parse(buf);
                    if (root) {
                        cJSON *name = cJSON_GetObjectItem(root, "name");
                        cJSON *address = cJSON_GetObjectItem(root, "address");
                        cJSON *public_key = cJSON_GetObjectItem(root, "public_key");
                        cJSON *private_key = cJSON_GetObjectItem(root, "private_key");
                        if (name && cJSON_IsString(name)) e->identity.name = portillia_gc_strdup(name->valuestring);
                        if (address && cJSON_IsString(address)) e->identity.address = portillia_gc_strdup(address->valuestring);
                        if (public_key && cJSON_IsString(public_key)) e->identity.public_key = portillia_gc_strdup(public_key->valuestring);
                        if (private_key && cJSON_IsString(private_key)) e->identity.private_key = portillia_gc_strdup(private_key->valuestring);
                        cJSON_Delete(root);
                    }
                }
                free(buf);
            }
            fclose(f);
        }
    } else if (cfg->identity_json && cfg->identity_json[0]) {
        cJSON *root = cJSON_Parse(cfg->identity_json);
        if (root) {
            cJSON *name = cJSON_GetObjectItem(root, "name");
            cJSON *address = cJSON_GetObjectItem(root, "address");
            cJSON *public_key = cJSON_GetObjectItem(root, "public_key");
            cJSON *private_key = cJSON_GetObjectItem(root, "private_key");
            if (name && cJSON_IsString(name)) e->identity.name = portillia_gc_strdup(name->valuestring);
            if (address && cJSON_IsString(address)) e->identity.address = portillia_gc_strdup(address->valuestring);
            if (public_key && cJSON_IsString(public_key)) e->identity.public_key = portillia_gc_strdup(public_key->valuestring);
            if (private_key && cJSON_IsString(private_key)) e->identity.private_key = portillia_gc_strdup(private_key->valuestring);
            cJSON_Delete(root);
        }
    }
    if (!e->identity.name && cfg->name) {
        e->identity.name = portillia_gc_strdup(cfg->name);
    }

    if (cfg->target_addr) e->target_addr = portillia_gc_strdup(cfg->target_addr);
    if (cfg->udp_addr) e->udp_addr = portillia_gc_strdup(cfg->udp_addr);
    e->udp_enabled = cfg->udp_enabled;
    e->tcp_enabled = cfg->tcp_enabled;
    e->multi_hop_depth = cfg->multi_hop_depth;
    e->ban_mitm = cfg->ban_mitm;
    e->insecure_skip_verify = cfg->insecure_skip_verify;
    e->max_active_relays = cfg->max_active_relays;
    e->max_routing = cfg->max_routing > 0 ? cfg->max_routing : 1;
    portillia_lease_metadata_copy(&e->metadata, &cfg->metadata);

    e->explicit_relays = string_list_copy(cfg->relay_urls, cfg->relay_urls_count);
    e->explicit_relays_count = cfg->relay_urls_count;

    e->multi_hop = string_list_copy(cfg->multi_hop, cfg->multi_hop_count);
    e->multi_hop_count = cfg->multi_hop_count;

    /* Initialize relay set */
    e->relay_set = portillia_relay_set_create((const char **)cfg->relay_urls, cfg->relay_urls_count);

    /* Create accepted channel */
    e->accepted = channel_new(128);
    if (!e->accepted) {
        portillia_exposure_close(e);
        errno = ENOMEM;
        return NULL;
    }

    /* Initial listener reconciliation */
    reconcile_relay_listeners(e, true);

    /* Start discovery loop if needed */
    if (cfg->discovery || e->multi_hop_count > 0 || e->multi_hop_depth > 1) {
        e->discovery_running = true;
        pthread_create(&e->discovery_tid, NULL, discovery_loop_thread, e);
    }

    LOG_INFO("SDK: Exposure created for target %s", e->target_addr ? e->target_addr : "(none)");

    return e;
}

int portillia_exposure_add_relay(portillia_exposure_t *e, const char *relay_url) {
    if (!e || !relay_url) return -1;
    if (exposure_done(e)) {
        errno = EBADF;
        return -1;
    }

    pthread_rwlock_wrlock(&e->listener_mu);
    if (!string_in_list(relay_url, e->explicit_relays, e->explicit_relays_count)) {
        char **next = (char **)portillia_gc_alloc(sizeof(char *) * (e->explicit_relays_count + 1));
        if (!next) {
            pthread_rwlock_unlock(&e->listener_mu);
            errno = ENOMEM;
            return -1;
        }
        for (size_t i = 0; i < e->explicit_relays_count; i++) {
            next[i] = e->explicit_relays[i];
        }
        next[e->explicit_relays_count] = portillia_gc_strdup(relay_url);
        portillia_gc_free_later(e->explicit_relays);
        e->explicit_relays = next;
        e->explicit_relays_count++;
    }

    /* Remove from seed-only if present. */
    if (e->seed_only_relays_count > 0) {
        size_t new_count = 0;
        for (size_t i = 0; i < e->seed_only_relays_count; i++) {
            if (!strings_equal(relay_url, e->seed_only_relays[i])) {
                e->seed_only_relays[new_count++] = e->seed_only_relays[i];
            } else {
                portillia_gc_free_later(e->seed_only_relays[i]);
            }
        }
        e->seed_only_relays_count = new_count;
    }
    pthread_rwlock_unlock(&e->listener_mu);

    if (e->relay_set) {
        portillia_relay_set_allow_url(e->relay_set, relay_url);
        portillia_relay_set_add_bootstrap_url(e->relay_set, relay_url);
    }
    reconcile_relay_listeners(e, false);
    return 0;
}

int portillia_exposure_remove_relay(portillia_exposure_t *e, const char *relay_url) {
    if (!e || !relay_url) return -1;
    if (exposure_done(e)) {
        errno = EBADF;
        return -1;
    }

    pthread_rwlock_wrlock(&e->listener_mu);

    /* Remove from explicit relays. */
    if (e->explicit_relays_count > 0) {
        size_t new_count = 0;
        for (size_t i = 0; i < e->explicit_relays_count; i++) {
            if (!strings_equal(relay_url, e->explicit_relays[i])) {
                e->explicit_relays[new_count++] = e->explicit_relays[i];
            } else {
                portillia_gc_free_later(e->explicit_relays[i]);
            }
        }
        e->explicit_relays_count = new_count;
    }

    /* Remove from seed-only relays. */
    if (e->seed_only_relays_count > 0) {
        size_t new_count = 0;
        for (size_t i = 0; i < e->seed_only_relays_count; i++) {
            if (!strings_equal(relay_url, e->seed_only_relays[i])) {
                e->seed_only_relays[new_count++] = e->seed_only_relays[i];
            } else {
                portillia_gc_free_later(e->seed_only_relays[i]);
            }
        }
        e->seed_only_relays_count = new_count;
    }

    /* Remove from multi-hop if present. */
    if (e->multi_hop_count > 0 && string_in_list(relay_url, e->multi_hop, e->multi_hop_count)) {
        size_t new_count = 0;
        for (size_t i = 0; i < e->multi_hop_count; i++) {
            if (!strings_equal(relay_url, e->multi_hop[i])) {
                e->multi_hop[new_count++] = e->multi_hop[i];
            } else {
                portillia_gc_free_later(e->multi_hop[i]);
            }
        }
        if (new_count < 2) {
            string_list_free(e->multi_hop, e->multi_hop_count);
            e->multi_hop = NULL;
            e->multi_hop_count = 0;
            e->multi_hop_depth = 0;
        } else {
            e->multi_hop_count = new_count;
        }
    }
    pthread_rwlock_unlock(&e->listener_mu);

    if (e->relay_set) {
        portillia_relay_set_ban_url(e->relay_set, relay_url);
        portillia_relay_set_remove_bootstrap_url(e->relay_set, relay_url);
    }
    reconcile_relay_listeners(e, false);
    return 0;
}

int portillia_exposure_seed_relay(portillia_exposure_t *e, const char *relay_url) {
    if (!e || !relay_url) return -1;
    if (exposure_done(e)) {
        errno = EBADF;
        return -1;
    }

    pthread_rwlock_wrlock(&e->listener_mu);

    /* Remove from explicit relays. */
    if (e->explicit_relays_count > 0) {
        size_t new_count = 0;
        for (size_t i = 0; i < e->explicit_relays_count; i++) {
            if (!strings_equal(relay_url, e->explicit_relays[i])) {
                e->explicit_relays[new_count++] = e->explicit_relays[i];
            } else {
                portillia_gc_free_later(e->explicit_relays[i]);
            }
        }
        e->explicit_relays_count = new_count;
    }

    /* Remove from multi-hop if present. */
    if (e->multi_hop_count > 0 && string_in_list(relay_url, e->multi_hop, e->multi_hop_count)) {
        size_t new_count = 0;
        for (size_t i = 0; i < e->multi_hop_count; i++) {
            if (!strings_equal(relay_url, e->multi_hop[i])) {
                e->multi_hop[new_count++] = e->multi_hop[i];
            } else {
                portillia_gc_free_later(e->multi_hop[i]);
            }
        }
        if (new_count < 2) {
            string_list_free(e->multi_hop, e->multi_hop_count);
            e->multi_hop = NULL;
            e->multi_hop_count = 0;
            e->multi_hop_depth = 0;
        } else {
            e->multi_hop_count = new_count;
        }
    }

    /* Add to seed-only if not already present. */
    if (!string_in_list(relay_url, e->seed_only_relays, e->seed_only_relays_count)) {
        char **next = (char **)portillia_gc_alloc(sizeof(char *) * (e->seed_only_relays_count + 1));
        if (!next) {
            pthread_rwlock_unlock(&e->listener_mu);
            errno = ENOMEM;
            return -1;
        }
        for (size_t i = 0; i < e->seed_only_relays_count; i++) {
            next[i] = e->seed_only_relays[i];
        }
        next[e->seed_only_relays_count] = portillia_gc_strdup(relay_url);
        portillia_gc_free_later(e->seed_only_relays);
        e->seed_only_relays = next;
        e->seed_only_relays_count++;
    }
    pthread_rwlock_unlock(&e->listener_mu);

    if (e->relay_set) {
        portillia_relay_set_allow_url(e->relay_set, relay_url);
        portillia_relay_set_add_bootstrap_url(e->relay_set, relay_url);
    }
    reconcile_relay_listeners(e, false);
    return 0;
}

int portillia_exposure_set_multi_hop(portillia_exposure_t *e, char **relay_urls, size_t count) {
    if (!e) return -1;
    if (exposure_done(e)) {
        errno = EBADF;
        return -1;
    }
    if (count == 1) {
        errno = EINVAL;
        return -1;
    }
    if ((count > 0 || e->multi_hop_depth > 1) && (e->udp_enabled || e->tcp_enabled)) {
        errno = EINVAL;
        return -1;
    }

    pthread_rwlock_wrlock(&e->listener_mu);
    if (e->multi_hop) {
        string_list_free(e->multi_hop, e->multi_hop_count);
    }
    e->multi_hop = string_list_copy(relay_urls, count);
    e->multi_hop_count = count;
    e->multi_hop_depth = 0;

    /* Remove seeded relays that are now in multi-hop. */
    if (e->seed_only_relays_count > 0) {
        size_t new_count = 0;
        for (size_t i = 0; i < e->seed_only_relays_count; i++) {
            if (!string_in_list(e->seed_only_relays[i], relay_urls, count)) {
                e->seed_only_relays[new_count++] = e->seed_only_relays[i];
            } else {
                portillia_gc_free_later(e->seed_only_relays[i]);
            }
        }
        e->seed_only_relays_count = new_count;
    }
    pthread_rwlock_unlock(&e->listener_mu);

    if (e->relay_set) {
        for (size_t i = 0; i < count; i++) {
            if (relay_urls[i]) {
                portillia_relay_set_allow_url(e->relay_set, relay_urls[i]);
                portillia_relay_set_add_bootstrap_url(e->relay_set, relay_urls[i]);
            }
        }
    }
    reconcile_relay_listeners(e, false);
    return 0;
}

char **portillia_exposure_active_relay_urls(portillia_exposure_t *e, size_t *out_count) {
    if (!e || !out_count) return NULL;
    *out_count = 0;

    pthread_rwlock_rdlock(&e->listener_mu);
    size_t count = e->listener_count;
    char **urls = NULL;
    if (count > 0) {
        urls = (char **)portillia_gc_alloc(sizeof(char *) * count);
        if (urls) {
            for (size_t i = 0; i < count; i++) {
                urls[i] = portillia_gc_strdup(e->listener_urls[i]);
            }
        }
    }
    pthread_rwlock_unlock(&e->listener_mu);
    *out_count = count;
    return urls;
}

portillia_net_addr_t portillia_exposure_addr(const portillia_exposure_t *e) {
    if (!e || !e->identity.address || !e->identity.address[0]) {
        return make_exposure_addr(NULL);
    }
    return make_exposure_addr(e->identity.address);
}

portillia_identity_t portillia_exposure_identity(const portillia_exposure_t *e) {
    portillia_identity_t id;
    portillia_identity_init(&id);
    if (e) {
        portillia_identity_copy(&id, &e->identity);
    }
    return id;
}

portillia_agent_tunnel_status_t portillia_exposure_snapshot(portillia_exposure_t *e) {
    portillia_agent_tunnel_status_t snap;
    portillia_agent_tunnel_status_init(&snap);
    if (!e) return snap;

    pthread_rwlock_rdlock(&e->listener_mu);
    if (e->target_addr) snap.target_addr = portillia_gc_strdup(e->target_addr);
    if (e->multi_hop_count > 0) {
        snap.multi_hop = string_list_copy(e->multi_hop, e->multi_hop_count);
        snap.multi_hop_count = e->multi_hop_count;
    }
    if (e->listener_count > 0) {
        snap.relays = (portillia_agent_relay_status_t *)portillia_gc_alloc(sizeof(portillia_agent_relay_status_t) * e->listener_count);
        if (snap.relays) {
            snap.relays_count = e->listener_count;
            for (size_t i = 0; i < e->listener_count; i++) {
                portillia_agent_relay_status_init(&snap.relays[i]);
                snap.relays[i].relay_url = portillia_gc_strdup(e->listener_urls[i]);
                snap.relays[i].connecting = true;
                char *pub_url = portillia_listener_public_url(e->listeners[i]);
                if (pub_url) {
                    snap.relays[i].public_url = pub_url;
                }
            }
        }
    }
    pthread_rwlock_unlock(&e->listener_mu);

    return snap;
}

int portillia_exposure_accept_datagram(portillia_exposure_t *e, portillia_datagram_frame_t *out_frame) {
    if (!e || !out_frame) return -1;
    if (!e->udp_enabled) {
        errno = EBADF;
        return -1;
    }
    /* Fan-in: iterate listeners and try non-blocking accept on each. */
    pthread_rwlock_rdlock(&e->listener_mu);
    for (size_t i = 0; i < e->listener_count; i++) {
        bool cancelled = false;
        if (portillia_listener_accept_datagram(e->listeners[i], out_frame, &cancelled) == 0) {
            pthread_rwlock_unlock(&e->listener_mu);
            return 0;
        }
    }
    pthread_rwlock_unlock(&e->listener_mu);
    errno = EAGAIN;
    return -1;
}

int portillia_exposure_send_datagram(portillia_exposure_t *e, const portillia_datagram_frame_t *frame) {
    if (!e || !frame) return -1;
    if (!e->udp_enabled) {
        errno = EBADF;
        return -1;
    }
    pthread_rwlock_rdlock(&e->listener_mu);
    int idx = listener_index_by_url(e, frame->relay_url);
    int ret = -1;
    if (idx >= 0) {
        ret = portillia_listener_send_datagram(e->listeners[idx], frame);
    } else {
        errno = ENOENT;
    }
    pthread_rwlock_unlock(&e->listener_mu);
    return ret;
}

char **portillia_exposure_wait_datagram_ready(portillia_exposure_t *e, int timeout_ms, size_t *out_count) {
    if (!e || !out_count) return NULL;
    *out_count = 0;
    if (!e->udp_enabled) {
        errno = EINVAL;
        return NULL;
    }
    /* Poll listeners for datagram readiness with timeout. */
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000;
    }

    pthread_rwlock_rdlock(&e->listener_mu);
    size_t cap = e->listener_count;
    char **addrs = NULL;
    size_t count = 0;
    if (cap > 0) {
        addrs = (char **)portillia_gc_alloc(sizeof(char *) * cap);
    }
    for (size_t i = 0; i < e->listener_count && addrs; i++) {
        bool ready = false, pending = false;
        char *addr = portillia_listener_datagram_ready(e->listeners[i], &ready, &pending);
        if (addr) {
            addrs[count++] = addr;
        }
    }
    pthread_rwlock_unlock(&e->listener_mu);
    *out_count = count;
    if (count == 0) {
        if (addrs) portillia_gc_free_later(addrs);
        errno = ETIMEDOUT;
        return NULL;
    }
    return addrs;
}

int portillia_exposure_run_http_routes(portillia_exposure_t *e,
                                        const portillia_http_route_t *routes,
                                        size_t routes_count,
                                        const char *local_addr) {
    if (!e || !routes || routes_count == 0) return -1;
    return portillia_http_server_run_routes(e, routes, routes_count, local_addr);
}

int portillia_exposure_run_http(portillia_exposure_t *e, void *handler, const char *local_addr) {
    if (!e) return -1;
    (void)handler;
    /* C port does not support generic HTTP handlers; use RunHTTPRoutes instead. */
    errno = ENOSYS;
    return -1;
}

portillia_net_conn_t *portillia_exposure_accept(portillia_exposure_t *e) {
    if (!e) {
        errno = EINVAL;
        return NULL;
    }
    if (exposure_done(e)) {
        errno = EBADF;
        return NULL;
    }
    portillia_conn_channel_t *ch = (portillia_conn_channel_t *)e->accepted;
    if (!ch) {
        errno = ENOSYS;
        return NULL;
    }
    bool closed = false;
    portillia_net_conn_t *conn = channel_pop(ch, &closed);
    if (!conn && closed) {
        errno = EBADF;
    }
    return conn;
}

/* ---------- Close with once semantics ---------- */

static void do_close(portillia_exposure_t *e) {
    if (!e) return;
    exposure_cancel(e);

    pthread_rwlock_wrlock(&e->listener_mu);
    /* Close all listeners first so accept threads wake up. */
    for (size_t i = 0; i < e->listener_count; i++) {
        if (e->listeners[i]) portillia_listener_close(e->listeners[i]);
        if (e->listener_urls[i]) portillia_gc_free_later(e->listener_urls[i]);
    }
    /* Join accept threads. */
    if (e->listener_accept_tids) {
        for (size_t i = 0; i < e->listener_count; i++) {
            pthread_join(e->listener_accept_tids[i], NULL);
        }
        portillia_gc_free_later(e->listener_accept_tids);
        e->listener_accept_tids = NULL;
    }
    if (e->listeners) portillia_gc_free_later(e->listeners);
    if (e->listener_urls) portillia_gc_free_later(e->listener_urls);
    e->listener_count = 0;
    e->listener_cap = 0;
    if (e->relay_set) {
        portillia_relay_set_free(e->relay_set);
        e->relay_set = NULL;
    }
    pthread_rwlock_unlock(&e->listener_mu);

    /* Wait for discovery thread to finish. */
    if (e->discovery_running) {
        e->discovery_running = false;
        pthread_join(e->discovery_tid, NULL);
    }

    /* Close accepted channel */
    if (e->accepted) {
        channel_free((portillia_conn_channel_t *)e->accepted);
        e->accepted = NULL;
    }

    /* Cleanup strings */
    if (e->target_addr) portillia_gc_free_later(e->target_addr);
    if (e->udp_addr) portillia_gc_free_later(e->udp_addr);
    string_list_free(e->explicit_relays, e->explicit_relays_count);
    string_list_free(e->seed_only_relays, e->seed_only_relays_count);
    string_list_free(e->multi_hop, e->multi_hop_count);
    portillia_identity_cleanup(&e->identity);
    portillia_lease_metadata_cleanup(&e->metadata);

    pthread_mutex_destroy(&e->cancel_mu);
    pthread_cond_destroy(&e->cancel_cond);
    pthread_rwlock_destroy(&e->listener_mu);

    LOG_INFO("SDK: Exposure closed");
}

void portillia_exposure_close(portillia_exposure_t *e) {
    if (!e) return;
    /* Simple idempotency: check cancelled flag. */
    if (atomic_exchange(&e->cancelled, true)) {
        return; /* already closed */
    }
    do_close(e);
    portillia_gc_free_later(e);
}

/* ---------- Connection helpers ---------- */

void portillia_net_conn_close(portillia_net_conn_t *conn) {
    if (!conn) return;
    if (conn->closed) return;
    conn->closed = true;
    portillia_net_conn_cleanup(conn);
    portillia_gc_free_later(conn);
}

ssize_t portillia_net_conn_read(portillia_net_conn_t *conn, void *buf, size_t len) {
    if (!conn || !buf) { errno = EINVAL; return -1; }
    if (conn->closed) { errno = EBADF; return -1; }
    if (conn->ssl) {
        /* inner TLS over outer TLS: pump from outer_ssl into inner rbio */
        int n = SSL_read(conn->ssl, buf, (int)len);
        if (n > 0) return (ssize_t)n;
        int err = SSL_get_error(conn->ssl, n);
        while (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (err == SSL_ERROR_WANT_READ) {
                char tmp[4096];
                int m = SSL_read(conn->outer_ssl, tmp, sizeof(tmp));
                if (m <= 0) {
                    int oerr = SSL_get_error(conn->outer_ssl, m);
                    if (oerr == SSL_ERROR_WANT_READ || oerr == SSL_ERROR_WANT_WRITE) {
                        errno = EAGAIN;
                        return -1;
                    }
                    errno = EIO;
                    return -1;
                }
                BIO_write(SSL_get_rbio(conn->ssl), tmp, m);
            } else { /* WANT_WRITE */
                char tmp[4096];
                int m = BIO_read(SSL_get_wbio(conn->ssl), tmp, sizeof(tmp));
                if (m > 0) {
                    int w = SSL_write(conn->outer_ssl, tmp, m);
                    if (w <= 0) {
                        int oerr = SSL_get_error(conn->outer_ssl, w);
                        if (oerr == SSL_ERROR_WANT_READ || oerr == SSL_ERROR_WANT_WRITE) {
                            errno = EAGAIN;
                            return -1;
                        }
                        errno = EIO;
                        return -1;
                    }
                }
            }
            n = SSL_read(conn->ssl, buf, (int)len);
            if (n > 0) return (ssize_t)n;
            err = SSL_get_error(conn->ssl, n);
        }
        errno = EIO;
        return -1;
    }
    if (conn->outer_ssl) {
        int n = SSL_read(conn->outer_ssl, buf, (int)len);
        if (n <= 0) {
            int err = SSL_get_error(conn->outer_ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                errno = EAGAIN;
            } else {
                errno = EIO;
            }
        }
        return (ssize_t)n;
    }
    return read(conn->fd, buf, len);
}

ssize_t portillia_net_conn_write(portillia_net_conn_t *conn, const void *buf, size_t len) {
    if (!conn || !buf) { errno = EINVAL; return -1; }
    if (conn->closed) { errno = EBADF; return -1; }
    if (conn->ssl) {
        /* inner TLS over outer TLS: write to inner, then pump wbio to outer */
        int n = SSL_write(conn->ssl, buf, (int)len);
        if (n > 0) {
            char tmp[4096];
            int m;
            while ((m = BIO_read(SSL_get_wbio(conn->ssl), tmp, sizeof(tmp))) > 0) {
                int w = 0;
                while (w < m) {
                    int wr = SSL_write(conn->outer_ssl, tmp + w, m - w);
                    if (wr <= 0) {
                        int oerr = SSL_get_error(conn->outer_ssl, wr);
                        if (oerr == SSL_ERROR_WANT_READ || oerr == SSL_ERROR_WANT_WRITE) {
                            errno = EAGAIN;
                            return -1;
                        }
                        errno = EIO;
                        return -1;
                    }
                    w += wr;
                }
            }
            return (ssize_t)n;
        }
        int err = SSL_get_error(conn->ssl, n);
        while (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (err == SSL_ERROR_WANT_WRITE) {
                char tmp[4096];
                int m = BIO_read(SSL_get_wbio(conn->ssl), tmp, sizeof(tmp));
                if (m > 0) {
                    int w = SSL_write(conn->outer_ssl, tmp, m);
                    if (w <= 0) {
                        int oerr = SSL_get_error(conn->outer_ssl, w);
                        if (oerr == SSL_ERROR_WANT_READ || oerr == SSL_ERROR_WANT_WRITE) {
                            errno = EAGAIN;
                            return -1;
                        }
                        errno = EIO;
                        return -1;
                    }
                }
            } else { /* WANT_READ */
                char tmp[4096];
                int m = SSL_read(conn->outer_ssl, tmp, sizeof(tmp));
                if (m <= 0) {
                    int oerr = SSL_get_error(conn->outer_ssl, m);
                    if (oerr == SSL_ERROR_WANT_READ || oerr == SSL_ERROR_WANT_WRITE) {
                        errno = EAGAIN;
                        return -1;
                    }
                    errno = EIO;
                    return -1;
                }
                BIO_write(SSL_get_rbio(conn->ssl), tmp, m);
            }
            n = SSL_write(conn->ssl, buf, (int)len);
            if (n > 0) {
                char tmp[4096];
                int m;
                while ((m = BIO_read(SSL_get_wbio(conn->ssl), tmp, sizeof(tmp))) > 0) {
                    int w = 0;
                    while (w < m) {
                        int wr = SSL_write(conn->outer_ssl, tmp + w, m - w);
                        if (wr <= 0) {
                            int oerr = SSL_get_error(conn->outer_ssl, wr);
                            if (oerr == SSL_ERROR_WANT_READ || oerr == SSL_ERROR_WANT_WRITE) {
                                errno = EAGAIN;
                                return -1;
                            }
                            errno = EIO;
                            return -1;
                        }
                        w += wr;
                    }
                }
                return (ssize_t)n;
            }
            err = SSL_get_error(conn->ssl, n);
        }
        errno = EIO;
        return -1;
    }
    if (conn->outer_ssl) {
        int n = SSL_write(conn->outer_ssl, buf, (int)len);
        if (n <= 0) {
            int err = SSL_get_error(conn->outer_ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                errno = EAGAIN;
            } else {
                errno = EIO;
            }
        }
        return (ssize_t)n;
    }
    return write(conn->fd, buf, len);
}

portillia_net_addr_t portillia_net_conn_local_addr(const portillia_net_conn_t *conn) {
    portillia_net_addr_t a = {0};
    if (conn) a = conn->local;
    return a;
}

portillia_net_addr_t portillia_net_conn_remote_addr(const portillia_net_conn_t *conn) {
    portillia_net_addr_t a = {0};
    if (conn) a = conn->remote;
    return a;
}

/* ---------- Discovery & reconciliation ---------- */

static int gcd_val(int a, int b) {
    while (b != 0) {
        int tmp = a % b;
        a = b;
        b = tmp;
    }
    return a < 0 ? -a : a;
}

static int pick_coprime_step(int n, int round) {
    if (n <= 1) return 1;
    int candidate = (round % (n - 1)) + 1;
    while (candidate < n) {
        if (gcd_val(candidate, n) == 1) return candidate;
        candidate++;
    }
    return 1;
}

typedef struct {
    char *url;
    double compensated;
} ols_url_weight_t;

static int compare_urls_alphabetical(const void *a, const void *b) {
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    if (!sa) return 1;
    if (!sb) return -1;
    return strcmp(sa, sb);
}

static int compare_ols_weights(const void *a, const void *b) {
    const ols_url_weight_t *wa = (const ols_url_weight_t *)a;
    const ols_url_weight_t *wb = (const ols_url_weight_t *)b;
    if (wa->compensated < wb->compensated) return -1;
    if (wa->compensated > wb->compensated) return 1;
    if (!wa->url) return 1;
    if (!wb->url) return -1;
    return strcmp(wa->url, wb->url);
}

static void *discovery_loop_thread(void *arg) {
    portillia_exposure_t *e = (portillia_exposure_t *)arg;
    uint64_t round = 0;
    while (e->discovery_running && !exposure_done(e)) {
        /* Try discovery on each explicit and seed relay. */
        pthread_rwlock_rdlock(&e->listener_mu);
        size_t url_count = e->explicit_relays_count + e->seed_only_relays_count;
        char **urls = NULL;
        if (url_count > 0) {
            urls = (char **)portillia_gc_alloc(sizeof(char *) * url_count);
            if (urls) {
                size_t idx = 0;
                for (size_t i = 0; i < e->explicit_relays_count; i++) {
                    urls[idx++] = portillia_gc_strdup(e->explicit_relays[i]);
                }
                for (size_t i = 0; i < e->seed_only_relays_count; i++) {
                    urls[idx++] = portillia_gc_strdup(e->seed_only_relays[i]);
                }
            }
        }
        pthread_rwlock_unlock(&e->listener_mu);

        if (urls) {
            if (url_count > 1) {
                /* 1. Sort alphabetically */
                qsort(urls, url_count, sizeof(char *), compare_urls_alphabetical);

                /* 2. Compute compensated load weights */
                ols_url_weight_t *weights = malloc(sizeof(ols_url_weight_t) * url_count);
                if (weights) {
                    for (size_t i = 0; i < url_count; i++) {
                        weights[i].url = urls[i];
                        double load = 0.0;
                        if (e->relay_set) {
                            pthread_rwlock_rdlock(&e->relay_set->mu);
                            portillia_relay_state_t *st = ttak_table_get((ttak_table_t *)e->relay_set->relays, urls[i], strlen(urls[i]), 0);
                            if (st) {
                                load = st->descriptor.load;
                            }
                            pthread_rwlock_unlock(&e->relay_set->mu);
                        }
                        if (isnan(load) || isinf(load) || load < 0) load = 0.0;
                        double distorted = load * load;
                        weights[i].compensated = sqrt(distorted + 1.0);
                    }

                    /* 3. Sort by compensated weights */
                    qsort(weights, url_count, sizeof(ols_url_weight_t), compare_ols_weights);

                    /* 4. Affine permutation */
                    int n = (int)url_count;
                    int a = pick_coprime_step(n, (int)round);
                    int b = (int)(round % (uint64_t)n);
                    
                    char **permuted_urls = malloc(sizeof(char *) * url_count);
                    if (permuted_urls) {
                        for (int i = 0; i < n; i++) {
                            int slot = (a * i + b) % n;
                            permuted_urls[i] = weights[slot].url;
                        }
                        /* Re-populate urls array */
                        for (size_t i = 0; i < url_count; i++) {
                            urls[i] = permuted_urls[i];
                        }
                        free(permuted_urls);
                    }
                    free(weights);
                }
            }

            int processed = 0;
            int max_r = e->max_routing > 0 ? e->max_routing : 1;
            for (size_t i = 0; i < url_count && e->discovery_running && !exposure_done(e); i++) {
                if (!urls[i]) continue;
                if (processed >= max_r) break;
                processed++;

                portillia_http_client_t *client = portillia_http_client_create(urls[i], e->insecure_skip_verify);
                if (!client) continue;
                portillia_discovery_response_t resp = {0};
                if (portillia_api_discover_relays(client, &resp) == 0) {
                    bool changed = false;
                    time_t now = time(NULL);
                    portillia_relay_set_apply_discovery_response(e->relay_set, urls[i], &resp, now, &changed);
                    if (changed) {
                        LOG_INFO("SDK: Discovery response from %s changed relay set", urls[i]);
                    }
                }
                portillia_discovery_response_cleanup(&resp);
                portillia_http_client_destroy(client);
            }
            for (size_t i = 0; i < url_count; i++) {
                if (urls[i]) portillia_gc_free_later(urls[i]);
            }
            portillia_gc_free_later(urls);
        }

        reconcile_relay_listeners(e, false);

        /* Sleep with early wakeup check. */
        for (int s = 0; s < PORTILLIA_DISCOVERY_POLL_INTERVAL_SEC && e->discovery_running && !exposure_done(e); s++) {
            sleep(1);
        }
        round++;
    }
    return NULL;
}

static int reconcile_relay_listeners(portillia_exposure_t *e, bool fail_on_error) {
    (void)fail_on_error;
    if (!e->relay_set) return 0;

    pthread_rwlock_wrlock(&e->listener_mu);

    /* Build desired relay URL list. */
    char **listener_relay_urls = NULL;
    size_t listener_relay_count = 0;

    if (e->multi_hop_count > 0) {
        /* Multi-hop: only exit relay gets a listener. */
        listener_relay_urls = (char **)portillia_gc_alloc(sizeof(char *) * 1);
        if (listener_relay_urls) {
            listener_relay_urls[0] = portillia_gc_strdup(e->multi_hop[e->multi_hop_count - 1]);
            listener_relay_count = 1;
        }
    } else if (e->multi_hop_depth > 1) {
        portillia_client_state_t client = {0};
        client.multi_hop_depth = e->multi_hop_depth;
        client.max_active_relays = e->max_active_relays > 0 ? e->max_active_relays : 4;
        client.require_udp = e->udp_enabled;
        client.require_tcp = e->tcp_enabled;
        client.local_address = e->target_addr;
        size_t mh_count = 0;
        char **mh_urls = portillia_relay_set_priority_multi_hop(e->relay_set, &client, &mh_count);
        if (mh_urls && mh_count > 0) {
            listener_relay_urls = (char **)portillia_gc_alloc(sizeof(char *) * mh_count);
            if (listener_relay_urls) {
                for (size_t i = 0; i < mh_count; i++) {
                    listener_relay_urls[i] = portillia_gc_strdup(mh_urls[i]);
                }
                listener_relay_count = mh_count;
            }
            portillia_gc_free_later(mh_urls);
        }
    } else {
        /* Single-hop: use explicit relays. */
        if (e->explicit_relays_count > 0) {
            listener_relay_urls = string_list_copy(e->explicit_relays, e->explicit_relays_count);
            listener_relay_count = e->explicit_relays_count;
        }
    }

    /* Identify stale listeners to remove. */
    size_t *remove_indices = NULL;
    size_t remove_count = 0;
    for (size_t i = 0; i < e->listener_count; i++) {
        bool wanted = false;
        for (size_t j = 0; j < listener_relay_count; j++) {
            if (strings_equal(e->listener_urls[i], listener_relay_urls[j])) {
                wanted = true;
                break;
            }
        }
        if (!wanted) {
            remove_indices = (size_t *)portillia_gc_realloc(remove_indices, sizeof(size_t) * (remove_count + 1));
            if (remove_indices) remove_indices[remove_count++] = i;
        }
    }

    /* Remove stale listeners (iterate backwards to preserve indices). */
    for (size_t i = remove_count; i > 0; i--) {
        exposure_remove_listener_at(e, remove_indices[i - 1]);
    }
    if (remove_indices) portillia_gc_free_later(remove_indices);

    /* Add missing listeners. */
    for (size_t j = 0; j < listener_relay_count; j++) {
        const char *url = listener_relay_urls[j];
        if (listener_index_by_url(e, url) >= 0) continue;

        /* Determine multi-hop for this listener. */
        char **listener_multi_hop = NULL;
        size_t listener_multi_hop_count = 0;
        if (e->multi_hop_count > 0 && strings_equal(url, e->multi_hop[e->multi_hop_count - 1])) {
            listener_multi_hop = e->multi_hop;
            listener_multi_hop_count = e->multi_hop_count;
        }

        portillia_listener_t *listener = portillia_listener_new(
            url, &e->identity, &e->metadata, e->relay_set,
            listener_multi_hop, listener_multi_hop_count,
            e->udp_enabled, e->tcp_enabled,
            0 /* retry_count: auto-selected relays get retries */,
            e->insecure_skip_verify
        );
        if (!listener) {
            LOG_WARN("SDK: Failed to create listener for %s", url);
            continue;
        }
        exposure_add_listener(e, url, listener);

        size_t idx = e->listener_count - 1;
        pthread_t *new_tids = (pthread_t *)portillia_gc_realloc(e->listener_accept_tids, sizeof(pthread_t) * e->listener_count);
        if (new_tids) {
            e->listener_accept_tids = new_tids;
            if (start_listener_accept_thread(e, listener, &e->listener_accept_tids[idx]) != 0) {
                LOG_WARN("SDK: Failed to start accept thread for %s", url);
            }
        }
    }

    if (listener_relay_urls) {
        for (size_t i = 0; i < listener_relay_count; i++) {
            if (listener_relay_urls[i]) portillia_gc_free_later(listener_relay_urls[i]);
        }
        portillia_gc_free_later(listener_relay_urls);
    }

    pthread_rwlock_unlock(&e->listener_mu);
    return 0;
}
