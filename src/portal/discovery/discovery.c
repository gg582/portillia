#include <portillia/portal/discovery/discovery.h>
#include <portillia/portal/settings.h>
#include <ttak/ttak.h>
#include <portillia/utils/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <portillia/utils/log.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "portal_bridge.h"

extern char* portillia_registry_to_json();

char g_desc_priv_hex[65] = {0};
char g_desc_addr[43] = {0};

static time_t parse_rfc3339_utc(const char *value) {
    if (!value || !value[0]) return 0;
    int y = 0, mon = 0, d = 0, h = 0, min = 0, s = 0;
    if (sscanf(value, "%d-%d-%dT%d:%d:%dZ", &y, &mon, &d, &h, &min, &s) != 6) return 0;
    struct tm tm = {0};
    tm.tm_year = y - 1900;
    tm.tm_mon = mon - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = min;
    tm.tm_sec = s;
    char *old_tz = getenv("TZ");
    char *saved = old_tz ? strdup(old_tz) : NULL;
    setenv("TZ", "UTC", 1);
    tzset();
    time_t t = mktime(&tm);
    if (saved) {
        setenv("TZ", saved, 1);
        free(saved);
    } else {
        unsetenv("TZ");
    }
    tzset();
    return t;
}

static void format_rfc3339_utc(time_t t, char *out, size_t out_len) {
    struct tm tm = {0};
    gmtime_r(&t, &tm);
    strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static int hex_to_bytes32(const char *hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned int v = 0;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static bool load_descriptor_identity_from_private_key(const char *private_key_hex) {
    if (!private_key_hex) return false;

    const char *hex = private_key_hex;
    if (strncmp(hex, "0x", 2) == 0 || strncmp(hex, "0X", 2) == 0) {
        hex += 2;
    }
    if (strlen(hex) != 64) return false;

    char tmp_addr[43] = {0};
    uint8_t priv[32];
    if (hex_to_bytes32(hex, priv) != 0) return false;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    bool ok = false;
    if (secp256k1_ec_seckey_verify(ctx, priv)) {
        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_create(ctx, &pubkey, priv)) {
            size_t pub_len = 65;
            uint8_t pub_buf[65];
            secp256k1_ec_pubkey_serialize(ctx, pub_buf, &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
            portillia_crypto_pubkey_to_address(pub_buf, pub_len, tmp_addr);
            snprintf(g_desc_priv_hex, sizeof(g_desc_priv_hex), "%s", hex);
            snprintf(g_desc_addr, sizeof(g_desc_addr), "%s", tmp_addr);
            ok = true;
        }
    }

    secp256k1_context_destroy(ctx);
    return ok;
}

static bool load_descriptor_identity_from_file(const char *identity_path_env) {
    if (!identity_path_env || !identity_path_env[0]) return false;

    char identity_file[1024];
    snprintf(identity_file, sizeof(identity_file), "%s/identity.json", identity_path_env);

    FILE *f = fopen(identity_file, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) {
        fclose(f);
        return false;
    }

    char *data = malloc((size_t)size + 1);
    if (!data) {
        fclose(f);
        return false;
    }
    if (fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return false;
    }
    data[size] = '\0';
    fclose(f);

    bool ok = false;
    cJSON *root = cJSON_Parse(data);
    if (root) {
        cJSON *private_key = cJSON_GetObjectItem(root, "private_key");
        if (private_key && cJSON_IsString(private_key) && private_key->valuestring) {
            ok = load_descriptor_identity_from_private_key(private_key->valuestring);
        }
        cJSON_Delete(root);
    }
    free(data);
    return ok;
}

void ensure_descriptor_identity() {
    if (g_desc_priv_hex[0] && g_desc_addr[0]) return;
    const char *env_priv = getenv("RELAY_DESCRIPTOR_PRIVATE_KEY");
    const char *identity_path = getenv("IDENTITY_PATH");
    if (env_priv && env_priv[0]) {
        (void)load_descriptor_identity_from_private_key(env_priv);
    }
    if ((!g_desc_priv_hex[0] || !g_desc_addr[0]) && identity_path && identity_path[0]) {
        (void)load_descriptor_identity_from_file(identity_path);
    }
    if (!g_desc_priv_hex[0] || !g_desc_addr[0]) {
        char priv_hex[65] = {0};
        char addr[43] = {0};
        if (portillia_crypto_generate_identity(priv_hex, addr) == 0) {
            snprintf(g_desc_priv_hex, sizeof(g_desc_priv_hex), "%s", priv_hex);
            snprintf(g_desc_addr, sizeof(g_desc_addr), "%s", addr);
            if (identity_path && identity_path[0]) {
                char identity_file[1024];
                snprintf(identity_file, sizeof(identity_file), "%s/identity.json", identity_path);
                FILE *f = fopen(identity_file, "wb");
                if (f) {
                    fprintf(f, "{\"private_key\":\"%s\"}\n", priv_hex);
                    fclose(f);
                }
            }
        }
    }
}

static int sign_descriptor_compact_b64(const char *canonical_json, char *out_b64, size_t out_len) {
    ensure_descriptor_identity();
    if (!canonical_json || !canonical_json[0] || !g_desc_priv_hex[0]) return -1;

    uint8_t seckey[32];
    if (hex_to_bytes32(g_desc_priv_hex, seckey) != 0) return -1;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t *)canonical_json, strlen(canonical_json), hash);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return -1;
    secp256k1_ecdsa_recoverable_signature sig;
    int recid = 0;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash, seckey, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    uint8_t compact64[64];
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, compact64, &recid, &sig);
    secp256k1_context_destroy(ctx);

    uint8_t compact65[65];
    compact65[0] = (uint8_t)(27 + recid + 4);
    memcpy(compact65 + 1, compact64, 64);

    size_t encoded_len = 4 * ((65 + 2) / 3);
    if (out_len <= encoded_len) return -1;
    EVP_EncodeBlock((unsigned char *)out_b64, compact65, 65);
    return 0;
}

static void build_canonical_descriptor_json(const portillia_relay_descriptor *d, char *out, size_t out_len) {
    long long issued_ns = (long long)d->issued_at * 1000000000LL;
    long long expires_ns = (long long)d->expires_at * 1000000000LL;
    snprintf(
        out,
        out_len,
        "{\"address\":\"%s\",\"version\":\"%s\",\"issued_at_unix_nano\":%lld,\"expires_at_unix_nano\":%lld,"
        "\"api_https_addr\":\"%s\",\"wireguard_public_key\":\"%s\",\"wireguard_port\":%d,"
        "\"supports_overlay\":%s,\"supports_udp\":%s,\"supports_tcp\":%s,"
        "\"active_connections\":%lld,\"tcp_bps\":%.17g}",
        d->address ? d->address : "",
        d->version ? d->version : "",
        issued_ns,
        expires_ns,
        d->api_https_addr ? d->api_https_addr : "",
        d->wireguard_public_key ? d->wireguard_public_key : "",
        d->wireguard_port,
        d->supports_overlay ? "true" : "false",
        d->supports_udp ? "true" : "false",
        d->supports_tcp ? "true" : "false",
        (long long)d->active_connections,
        d->tcp_bps
    );
}

portillia_relay_set* portillia_relay_set_new() {
    portillia_relay_set *set = calloc(1, sizeof(portillia_relay_set));
    pthread_mutex_init(&set->mu, NULL);
    return set;
}

void portillia_discovery_relay_set_free(portillia_relay_set *set) {
    if (!set) return;
    for (int i = 0; i < set->count; i++) {
        free(set->relays[i].descriptor.address);
        free(set->relays[i].descriptor.version);
        free(set->relays[i].descriptor.api_https_addr);
        free(set->relays[i].descriptor.wireguard_public_key);
        free(set->relays[i].descriptor.signature);
    }
    pthread_mutex_destroy(&set->mu);
    free(set);
}

void portillia_relay_set_upsert(portillia_relay_set *set, portillia_relay_descriptor desc) {
    pthread_mutex_lock(&set->mu);
    for (int i = 0; i < set->count; i++) {
        if (strcmp(set->relays[i].descriptor.api_https_addr, desc.api_https_addr ? desc.api_https_addr : "") == 0) {
            free(set->relays[i].descriptor.address);
            free(set->relays[i].descriptor.version);
            free(set->relays[i].descriptor.wireguard_public_key);
            free(set->relays[i].descriptor.signature);
            set->relays[i].descriptor.address = strdup(desc.address ? desc.address : "");
            set->relays[i].descriptor.version = strdup(desc.version ? desc.version : "");
            set->relays[i].descriptor.wireguard_public_key = strdup(desc.wireguard_public_key ? desc.wireguard_public_key : "");
            set->relays[i].descriptor.signature = strdup(desc.signature ? desc.signature : "");
            set->relays[i].descriptor.issued_at = desc.issued_at;
            set->relays[i].descriptor.expires_at = desc.expires_at;
            set->relays[i].descriptor.wireguard_port = desc.wireguard_port;
            set->relays[i].descriptor.supports_overlay = desc.supports_overlay;
            set->relays[i].descriptor.supports_udp = desc.supports_udp;
            set->relays[i].descriptor.supports_tcp = desc.supports_tcp;
            set->relays[i].descriptor.active_connections = desc.active_connections;
            set->relays[i].descriptor.tcp_bps = desc.tcp_bps;
            pthread_mutex_unlock(&set->mu);
            return;
        }
    }
    if (set->count < MAX_RELAYS) {
        set->relays[set->count].descriptor.address = strdup(desc.address ? desc.address : "");
        set->relays[set->count].descriptor.version = strdup(desc.version ? desc.version : "");
        set->relays[set->count].descriptor.api_https_addr = strdup(desc.api_https_addr ? desc.api_https_addr : "");
        set->relays[set->count].descriptor.wireguard_public_key = strdup(desc.wireguard_public_key ? desc.wireguard_public_key : "");
        set->relays[set->count].descriptor.signature = strdup(desc.signature ? desc.signature : "");
        set->relays[set->count].descriptor.issued_at = desc.issued_at;
        set->relays[set->count].descriptor.expires_at = desc.expires_at;
        set->relays[set->count].descriptor.wireguard_port = desc.wireguard_port;
        set->relays[set->count].descriptor.supports_overlay = desc.supports_overlay;
        set->relays[set->count].descriptor.supports_udp = desc.supports_udp;
        set->relays[set->count].descriptor.supports_tcp = desc.supports_tcp;
        set->relays[set->count].descriptor.active_connections = desc.active_connections;
        set->relays[set->count].descriptor.tcp_bps = desc.tcp_bps;
        set->count++;
    }
    pthread_mutex_unlock(&set->mu);
}

static cJSON* discovery_relays_array(cJSON *root) {
    if (!root) return NULL;
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (data && cJSON_IsObject(data)) {
        cJSON *relays = cJSON_GetObjectItem(data, "relays");
        if (cJSON_IsArray(relays)) return relays;
    }
    cJSON *relays = cJSON_GetObjectItem(root, "relays");
    if (cJSON_IsArray(relays)) return relays;
    return NULL;
}

void portillia_discovery_poll(discovery_config *cfg, const char *url) {
    char full_url[1024];
    snprintf(full_url, sizeof(full_url), "%s/discovery", url);

    char *res_data = DiscoveryPollJSON(full_url);
    if (!res_data) {
        LOG_WARN("discovery poll failed url=%s", url);
        return;
    }

    cJSON *root = cJSON_Parse(res_data);
    FreeCString(res_data);
    if (root) {
        cJSON *relays = discovery_relays_array(root);
        if (cJSON_IsArray(relays)) {
            int size = cJSON_GetArraySize(relays);
            LOG_DEBUG("discovery poll succeeded url=%s relays=%d", url, size);
            for (int i = 0; i < size; i++) {
                cJSON *item = cJSON_GetArrayItem(relays, i);
                cJSON *addr = cJSON_GetObjectItem(item, "address");
                cJSON *version = cJSON_GetObjectItem(item, "version");
                cJSON *issued = cJSON_GetObjectItem(item, "issued_at");
                cJSON *expires = cJSON_GetObjectItem(item, "expires_at");
                cJSON *api_addr = cJSON_GetObjectItem(item, "api_https_addr");
                cJSON *wg_pubkey = cJSON_GetObjectItem(item, "wireguard_public_key");
                cJSON *wg_port = cJSON_GetObjectItem(item, "wireguard_port");
                cJSON *supports_overlay = cJSON_GetObjectItem(item, "supports_overlay");
                cJSON *supports_udp = cJSON_GetObjectItem(item, "supports_udp");
                cJSON *supports_tcp = cJSON_GetObjectItem(item, "supports_tcp");
                cJSON *active_connections = cJSON_GetObjectItem(item, "active_connections");
                cJSON *tcp_bps = cJSON_GetObjectItem(item, "tcp_bps");
                cJSON *signature = cJSON_GetObjectItem(item, "signature");
                if (api_addr && api_addr->valuestring) {
                    portillia_relay_descriptor d = {0};
                    d.address = strdup((addr && cJSON_IsString(addr) && addr->valuestring) ? addr->valuestring : "");
                    d.version = strdup((version && cJSON_IsString(version) && version->valuestring) ? version->valuestring : "");
                    d.api_https_addr = strdup(api_addr->valuestring);
                    d.wireguard_public_key = strdup((wg_pubkey && cJSON_IsString(wg_pubkey) && wg_pubkey->valuestring) ? wg_pubkey->valuestring : "");
                    d.signature = strdup((signature && cJSON_IsString(signature) && signature->valuestring) ? signature->valuestring : "");
                    d.issued_at = (issued && cJSON_IsString(issued) && issued->valuestring) ? parse_rfc3339_utc(issued->valuestring) : time(NULL);
                    d.expires_at = (expires && cJSON_IsString(expires) && expires->valuestring) ? parse_rfc3339_utc(expires->valuestring) : (time(NULL) + 60);
                    d.wireguard_port = (wg_port && cJSON_IsNumber(wg_port)) ? wg_port->valueint : 0;
                    d.supports_overlay = supports_overlay ? cJSON_IsTrue(supports_overlay) : false;
                    d.supports_udp = supports_udp ? cJSON_IsTrue(supports_udp) : false;
                    d.supports_tcp = supports_tcp ? cJSON_IsTrue(supports_tcp) : false;
                    d.active_connections = (active_connections && cJSON_IsNumber(active_connections)) ? (int64_t)active_connections->valuedouble : 0;
                    d.tcp_bps = (tcp_bps && cJSON_IsNumber(tcp_bps)) ? tcp_bps->valuedouble : 0.0;
                    portillia_relay_set_upsert(cfg->relay_set, d);
                    free(d.address);
                    free(d.version);
                    free(d.api_https_addr);
                    free(d.wireguard_public_key);
                    free(d.signature);
                }
            }
        }
        cJSON_Delete(root);
    } else {
        LOG_WARN("discovery poll parse failed url=%s", url);
    }
}

typedef struct {
    discovery_config *cfg;
    char *peer_url;
    const char *announce_json;
} announce_peer_args;

static void *announce_peer_worker(void *arg) {
    announce_peer_args *a = (announce_peer_args *)arg;
    portillia_discovery_poll(a->cfg, a->peer_url);

    char announce_url[1024];
    snprintf(announce_url, sizeof(announce_url), "%s/discovery/announce", a->peer_url);
    char *res_data = DiscoveryAnnounceJSON(announce_url, (char *)a->announce_json);
    if (res_data) {
        LOG_DEBUG("relay discovery announce succeeded relay=%s", a->peer_url);
        FreeCString(res_data);
    } else {
        LOG_WARN("relay discovery announce failed relay=%s", a->peer_url);
    }
    free(a->peer_url);
    free(a);
    return NULL;
}

static char *build_announce_payload(const portillia_relay_descriptor *desc) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "protocol_version", PORTILLIA_DISCOVERY_VERSION);
    cJSON *d = cJSON_CreateObject();
    char issued_at[64] = {0};
    char expires_at[64] = {0};
    format_rfc3339_utc(desc->issued_at, issued_at, sizeof(issued_at));
    format_rfc3339_utc(desc->expires_at, expires_at, sizeof(expires_at));
    cJSON_AddStringToObject(d, "address", desc->address ? desc->address : "");
    cJSON_AddStringToObject(d, "version", desc->version ? desc->version : PORTILLIA_DISCOVERY_VERSION);
    cJSON_AddStringToObject(d, "issued_at", issued_at);
    cJSON_AddStringToObject(d, "expires_at", expires_at);
    cJSON_AddStringToObject(d, "api_https_addr", desc->api_https_addr ? desc->api_https_addr : "");
    cJSON_AddStringToObject(d, "wireguard_public_key", desc->wireguard_public_key ? desc->wireguard_public_key : "");
    cJSON_AddNumberToObject(d, "wireguard_port", (double)desc->wireguard_port);
    cJSON_AddBoolToObject(d, "supports_overlay", desc->supports_overlay);
    cJSON_AddBoolToObject(d, "supports_udp", desc->supports_udp);
    cJSON_AddBoolToObject(d, "supports_tcp", desc->supports_tcp);
    cJSON_AddNumberToObject(d, "active_connections", (double)desc->active_connections);
    cJSON_AddNumberToObject(d, "tcp_bps", desc->tcp_bps);
    cJSON_AddStringToObject(d, "signature", desc->signature ? desc->signature : "");
    cJSON_AddItemToObject(root, "descriptor", d);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

static char *trim_inplace(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
    return s;
}

void portillia_discovery_announce(discovery_config *cfg, portillia_relay_descriptor *desc) {
    if (!cfg->bootstrap_urls) return;

    char *json = build_announce_payload(desc);
    if (!json) return;

    char *copy = strdup(cfg->bootstrap_urls);
    if (!copy) { free(json); return; }

    pthread_t tids[MAX_RELAYS];
    int n = 0;
    char *saveptr = NULL;
    for (char *token = strtok_r(copy, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
        token = trim_inplace(token);
        if (!*token || strcmp(token, cfg->relay_url) == 0) continue;
        if (n >= MAX_RELAYS) break;

        announce_peer_args *a = malloc(sizeof(*a));
        if (!a) continue;
        a->cfg = cfg;
        a->peer_url = strdup(token);
        a->announce_json = json;
        if (!a->peer_url || pthread_create(&tids[n], NULL, announce_peer_worker, a) != 0) {
            free(a->peer_url);
            free(a);
            continue;
        }
        n++;
    }
    for (int i = 0; i < n; i++) pthread_join(tids[i], NULL);

    free(copy);
    free(json);
}

extern int64_t portillia_proxy_get_active_conns();
extern double portillia_proxy_get_current_bps();
extern portillia_settings* portillia_server_get_settings();

static void discovery_task(ttak_task_t *task, void *arg) {
    (void)task;
    discovery_config *cfg = (discovery_config *)arg;
    if (!cfg || !cfg->relay_url || !cfg->advertise_url) {
        return;
    }

    portillia_relay_descriptor desc = {0};
    ensure_descriptor_identity();
    desc.address = strdup(g_desc_addr);
    desc.api_https_addr = strdup(cfg->advertise_url);
    desc.version = strdup(PORTILLIA_DISCOVERY_VERSION);
    desc.wireguard_public_key = strdup("");
    desc.signature = strdup("");
    desc.issued_at = time(NULL);
    desc.expires_at = desc.issued_at + 300;
    
    desc.active_connections = portillia_proxy_get_active_conns();
    desc.tcp_bps = portillia_proxy_get_current_bps();

    // WireGuard Info
    const char *identity_path = getenv("IDENTITY_PATH");
    char wg_pub[128] = {0};
    if (identity_path && identity_path[0]) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/identity.json", identity_path);
        FILE *f = fopen(path, "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long size = ftell(f);
            fseek(f, 0, SEEK_SET);
            char *json = malloc(size + 1);
            if (json) {
                fread(json, 1, size, f);
                json[size] = '\0';
                cJSON *root = cJSON_Parse(json);
                if (root) {
                    cJSON *wg = cJSON_GetObjectItem(root, "wireguard_public_key");
                    if (cJSON_IsString(wg) && wg->valuestring) {
                        strncpy(wg_pub, wg->valuestring, sizeof(wg_pub) - 1);
                    }
                    cJSON_Delete(root);
                }
                free(json);
            }
            fclose(f);
        }
    }
    free(desc.wireguard_public_key);
    desc.wireguard_public_key = strdup(wg_pub[0] ? wg_pub : "");
    desc.wireguard_port = (wg_pub[0] && cfg->wireguard_port > 0) ? cfg->wireguard_port : 0;
    desc.supports_overlay = (wg_pub[0]) ? true : false;
    portillia_settings *settings = portillia_server_get_settings();
    desc.supports_udp = settings ? settings->udp_enabled : false;
    desc.supports_tcp = settings ? settings->tcp_port_enabled : true;

    char canonical[2048] = {0};
    build_canonical_descriptor_json(&desc, canonical, sizeof(canonical));
    LOG_DEBUG("discovery canonical json=%s", canonical);
    char sig_b64[256] = {0};
    if (sign_descriptor_compact_b64(canonical, sig_b64, sizeof(sig_b64)) == 0) {
        free(desc.signature);
        desc.signature = strdup(sig_b64);
    } else {
        free(desc.signature);
        desc.signature = strdup("");
    }

    if (cfg->relay_set) {
        portillia_relay_set_upsert(cfg->relay_set, desc);
    }
    
    portillia_discovery_announce(cfg, &desc);
    
    // Sync peer list to Go overlay stack
    if (cfg->relay_set) {
        cJSON *arr = cJSON_CreateArray();
        pthread_mutex_lock(&cfg->relay_set->mu);
        for (int i = 0; i < cfg->relay_set->count; i++) {
            portillia_relay_descriptor *d = &cfg->relay_set->relays[i].descriptor;
            cJSON *state = cJSON_CreateObject();
            cJSON *dj = cJSON_CreateObject();
            cJSON_AddStringToObject(dj, "address", d->address ? d->address : "");
            cJSON_AddStringToObject(dj, "version", d->version ? d->version : "");
            cJSON_AddStringToObject(dj, "api_https_addr", d->api_https_addr ? d->api_https_addr : "");
            cJSON_AddStringToObject(dj, "wireguard_public_key", d->wireguard_public_key ? d->wireguard_public_key : "");
            cJSON_AddNumberToObject(dj, "wireguard_port", (double)d->wireguard_port);
            cJSON_AddBoolToObject(dj, "supports_overlay", d->supports_overlay);
            cJSON_AddBoolToObject(dj, "supports_udp", d->supports_udp);
            cJSON_AddBoolToObject(dj, "supports_tcp", d->supports_tcp);
            cJSON_AddNumberToObject(dj, "active_connections", (double)d->active_connections);
            cJSON_AddNumberToObject(dj, "tcp_bps", d->tcp_bps);
            cJSON_AddStringToObject(dj, "signature", d->signature ? d->signature : "");
            cJSON_AddItemToObject(state, "Descriptor", dj);
            cJSON_AddItemToArray(arr, state);
        }
        pthread_mutex_unlock(&cfg->relay_set->mu);
        char *sync_json = cJSON_PrintUnformatted(arr);
        cJSON_Delete(arr);
        if (sync_json) {
            OverlaySyncJSON(sync_json);
            free(sync_json);
        }
    }
    
    free(desc.address);
    free(desc.api_https_addr);
    free(desc.wireguard_public_key);
    free(desc.version);
    free(desc.signature);
}

void portillia_discovery_publish_self(discovery_config *cfg) {
    discovery_task(NULL, cfg);
}

void *discovery_maintenance_loop(void *arg) {
    discovery_config *cfg = (discovery_config *)arg;
    while (1) {
        discovery_task(NULL, cfg);
        sleep(30);
    }
    return NULL;
}
