#include <portillia/portal/discovery/discovery.h>
#include <ttak/ttak.h>
#include <portillia/utils/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <portillia/utils/log.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

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

void ensure_descriptor_identity() {
    if (g_desc_priv_hex[0] && g_desc_addr[0]) return;
    const char *env_priv = getenv("RELAY_DESCRIPTOR_PRIVATE_KEY");
    if (env_priv && strlen(env_priv) == 64) {
        char tmp_addr[43] = {0};
        uint8_t priv[32];
        if (hex_to_bytes32(env_priv, priv) == 0) {
            secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            if (ctx && secp256k1_ec_seckey_verify(ctx, priv)) {
                secp256k1_pubkey pubkey;
                if (secp256k1_ec_pubkey_create(ctx, &pubkey, priv)) {
                    size_t pub_len = 65;
                    uint8_t pub_buf[65];
                    secp256k1_ec_pubkey_serialize(ctx, pub_buf, &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
                    portillia_crypto_pubkey_to_address(pub_buf, pub_len, tmp_addr);
                    snprintf(g_desc_priv_hex, sizeof(g_desc_priv_hex), "%s", env_priv);
                    snprintf(g_desc_addr, sizeof(g_desc_addr), "%s", tmp_addr);
                }
            }
            if (ctx) secp256k1_context_destroy(ctx);
        }
    }
    if (!g_desc_priv_hex[0] || !g_desc_addr[0]) {
        char priv_hex[65] = {0};
        char addr[43] = {0};
        if (portillia_crypto_generate_identity(priv_hex, addr) == 0) {
            snprintf(g_desc_priv_hex, sizeof(g_desc_priv_hex), "%s", priv_hex);
            snprintf(g_desc_addr, sizeof(g_desc_addr), "%s", addr);
        }
    }
}

static int sign_descriptor_compact_b64(const char *canonical_json, char *out_b64, size_t out_len) {
    ensure_descriptor_identity();
    LOG_INFO("SIGN_PRIV_KEY priv=%s addr=%s", g_desc_priv_hex, g_desc_addr);
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

struct curl_response {
    char *data;
    size_t size;
};

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_response *mem = (struct curl_response *)userp;
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
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
    CURL *curl = curl_easy_init();
    if (!curl) return;

    struct curl_response res = { .data = malloc(1), .size = 0 };
    res.data[0] = '\0';

    char full_url[1024];
    snprintf(full_url, sizeof(full_url), "%s/discovery", url);

    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&res);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode code = curl_easy_perform(curl);
    if (code == CURLE_OK) {
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        cJSON *root = cJSON_Parse(res.data);
        if (root) {
            cJSON *relays = discovery_relays_array(root);
            if (cJSON_IsArray(relays)) {
                int size = cJSON_GetArraySize(relays);
                LOG_INFO("discovery poll succeeded url=%s status=%ld relays=%d", url, status, size);
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
    } else {
        LOG_WARN("discovery poll failed url=%s error=%s", url, curl_easy_strerror(code));
    }

    free(res.data);
    curl_easy_cleanup(curl);
}

void portillia_discovery_announce(discovery_config *cfg, portillia_relay_descriptor *desc) {
    // Periodic poll of bootstraps
    if (cfg->bootstrap_urls) {
        char *copy = strdup(cfg->bootstrap_urls);
        char *saveptr = NULL;
        char *token = strtok_r(copy, ",", &saveptr);
        while (token) {
            while (*token == ' ' || *token == '\t' || *token == '\n' || *token == '\r') token++;
            size_t token_len = strlen(token);
            while (token_len > 0 &&
                   (token[token_len - 1] == ' ' || token[token_len - 1] == '\t' || token[token_len - 1] == '\n' || token[token_len - 1] == '\r')) {
                token[--token_len] = '\0';
            }
            if (strcmp(token, cfg->relay_url) != 0) {
                portillia_discovery_poll(cfg, token);
                
                // Also send self-announce
                CURL *curl = curl_easy_init();
                char announce_url[1024];
                snprintf(announce_url, sizeof(announce_url), "%s/discovery/announce", token);
                
                cJSON *root = cJSON_CreateObject();
                cJSON_AddStringToObject(root, "protocol_version", "7");
                cJSON *d = cJSON_CreateObject();
                char issued_at[64] = {0};
                char expires_at[64] = {0};
                format_rfc3339_utc(desc->issued_at, issued_at, sizeof(issued_at));
                format_rfc3339_utc(desc->expires_at, expires_at, sizeof(expires_at));
                cJSON_AddStringToObject(d, "address", desc->address ? desc->address : "");
                cJSON_AddStringToObject(d, "version", desc->version ? desc->version : "7");
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
                LOG_INFO("relay discovery announce payload=%s", json);
                
                struct curl_slist *announce_headers = NULL;
                announce_headers = curl_slist_append(announce_headers, "Content-Type: application/json");
                struct curl_response res = { .data = malloc(1), .size = 0 };
                res.data[0] = '\0';
                curl_easy_setopt(curl, CURLOPT_URL, announce_url);
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, announce_headers);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
                CURLcode code = curl_easy_perform(curl);
                if (code == CURLE_OK) {
                    long status = 0;
                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
                    if (status >= 200 && status < 300) {
                        LOG_INFO("relay discovery announce succeeded relay=%s", token);
                    } else {
                        LOG_WARN("relay discovery announce failed error=\"http status %ld\" relay=%s response=%s", status, token, res.data ? res.data : "");
                    }
                } else {
                    LOG_WARN("relay discovery announce failed error=\"%s\" relay=%s", curl_easy_strerror(code), token);
                }
                free(res.data);
                
                free(json);
                cJSON_Delete(root);
                curl_slist_free_all(announce_headers);
                curl_easy_cleanup(curl);
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        free(copy);
    }
}

extern int64_t portillia_proxy_get_active_conns();
extern double portillia_proxy_get_current_bps();

static void discovery_task(ttak_task_t *task, void *arg) {
    (void)task;
    discovery_config *cfg = (discovery_config *)arg;
    if (!cfg || !cfg->relay_url) {
        return;
    }

    portillia_relay_descriptor desc = {0};
    ensure_descriptor_identity();
    LOG_INFO("DISCOVERY_IDENTITY priv=%s addr=%s", g_desc_priv_hex, g_desc_addr);
    desc.address = strdup(g_desc_addr);
    desc.api_https_addr = strdup(cfg->relay_url);
    desc.version = strdup("7");
    desc.wireguard_public_key = strdup("");
    desc.signature = strdup("");
    desc.issued_at = time(NULL);
    desc.expires_at = desc.issued_at + 300;
    
    desc.active_connections = portillia_proxy_get_active_conns();
    desc.tcp_bps = portillia_proxy_get_current_bps();

    // WireGuard Info
    const char *wg_pub = getenv("WIREGUARD_PUBLIC_KEY");
    free(desc.wireguard_public_key);
    desc.wireguard_public_key = strdup(wg_pub ? wg_pub : "");
    desc.wireguard_port = (wg_pub && wg_pub[0]) ? 51820 : 0;
    desc.supports_overlay = (wg_pub && wg_pub[0]) ? true : false;
    desc.supports_udp = false;
    desc.supports_tcp = true;

    char canonical[2048] = {0};
    build_canonical_descriptor_json(&desc, canonical, sizeof(canonical));
    LOG_INFO("discovery canonical json=%s", canonical);
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
