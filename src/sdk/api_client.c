/** @file api_client.c
 * @brief SDK HTTP API client implementation.
 */

#include <portillia/sdk/api_client.h>
#include <portillia/utils/crypto.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define SDK_PATH_DOMAIN "/sdk/domain"
#define SDK_PATH_REGISTER_CHALLENGE "/sdk/register/challenge"
#define SDK_PATH_REGISTER "/sdk/register"
#define SDK_PATH_RENEW "/sdk/renew"
#define SDK_PATH_UNREGISTER "/sdk/unregister"
#define SDK_PATH_HOP "/sdk/hop"
#define SDK_PATH_DISCOVERY "/discovery"

struct portillia_http_client {
    char *relay_url;
    CURL *curl;
    bool insecure_skip_verify;
};

/* ---------- Normalization helpers ---------- */

static void str_trim(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    size_t start = 0;
    while (start < len && isspace((unsigned char)s[start])) start++;
    size_t end = len;
    while (end > start && isspace((unsigned char)s[end - 1])) end--;
    memmove(s, s + start, end - start);
    s[end - start] = '\0';
}

static void str_tolower_inplace(char *s) {
    if (!s) return;
    for (size_t i = 0; s[i]; i++) {
        s[i] = (char)tolower((unsigned char)s[i]);
    }
}

static char *trim_hex_prefix(const char *s) {
    if (!s) return strdup("");
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return strdup(s + 2);
    return strdup(s);
}

static char *normalize_hostname(const char *raw) {
    if (!raw) return strdup("");
    char *h = strdup(raw);
    str_trim(h);
    str_tolower_inplace(h);
    size_t len = strlen(h);
    if (len > 0 && h[len - 1] == '.') h[len - 1] = '\0';
    return h;
}

static char *sanitize_dns_label_input(const char *raw) {
    if (!raw) return strdup("");
    char *input = strdup(raw);
    str_trim(input);
    str_tolower_inplace(input);
    if (!input[0]) { free(input); return strdup(""); }
    char *b = (char *)malloc(strlen(input) + 1);
    if (!b) { free(input); return NULL; }
    size_t j = 0;
    bool prev_hyphen = false;
    for (size_t i = 0; input[i]; i++) {
        unsigned char c = input[i];
        if (c == '-' || isalpha(c) || isdigit(c)) {
            b[j++] = (char)c;
            prev_hyphen = false;
        } else {
            if (prev_hyphen) continue;
            b[j++] = '-';
            prev_hyphen = true;
        }
    }
    b[j] = '\0';
    free(input);
    size_t len = strlen(b);
    size_t start = 0;
    while (start < len && b[start] == '-') start++;
    size_t end = len;
    while (end > start && b[end - 1] == '-') end--;
    char *out = (char *)malloc(end - start + 1);
    if (!out) { free(b); return NULL; }
    memcpy(out, b + start, end - start);
    out[end - start] = '\0';
    free(b);
    return out;
}

static char *normalize_dns_label(const char *raw) {
    char *label = sanitize_dns_label_input(raw);
    if (!label || !label[0]) { free(label); return NULL; }
    if (strchr(label, '.')) { free(label); return NULL; }
    if (strlen(label) > 63) { free(label); return NULL; }
    if (label[0] == '-' || label[strlen(label) - 1] == '-') { free(label); return NULL; }
    for (size_t i = 0; label[i]; i++) {
        char c = label[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
            free(label);
            return NULL;
        }
    }
    return label;
}

static char *normalize_relay_url(const char *raw) {
    if (!raw) return NULL;
    char *trimmed = strdup(raw);
    str_trim(trimmed);
    if (!trimmed[0]) { free(trimmed); return NULL; }
    if (!strstr(trimmed, "://")) {
        size_t len = strlen(trimmed);
        char *tmp = (char *)malloc(len + 10);
        if (!tmp) { free(trimmed); return NULL; }
        snprintf(tmp, len + 10, "https://%s", trimmed);
        free(trimmed);
        trimmed = tmp;
    }
    if (strncasecmp(trimmed, "https://", 8) != 0) {
        free(trimmed);
        return NULL;
    }
    const char *host_start = trimmed + 8;
    const char *query = strchr(host_start, '?');
    const char *frag = strchr(host_start, '#');
    const char *end = host_start + strlen(host_start);
    if (query && query < end) end = query;
    if (frag && frag < end) end = frag;
    size_t hp_len = end - host_start;
    char *host_path = (char *)malloc(hp_len + 1);
    if (!host_path) { free(trimmed); return NULL; }
    memcpy(host_path, host_start, hp_len);
    host_path[hp_len] = '\0';
    while (hp_len > 0 && host_path[hp_len - 1] == '/') {
        host_path[--hp_len] = '\0';
    }
    size_t hlen = strlen(host_path);
    if (hlen >= 6 && strncasecmp(host_path + hlen - 6, "/relay", 6) == 0) {
        host_path[hlen - 6] = '\0';
    }
    if (!host_path[0] || host_path[0] == '/') {
        free(host_path);
        free(trimmed);
        return NULL;
    }
    char *result = (char *)malloc(9 + strlen(host_path) + 1);
    if (!result) {
        free(host_path);
        free(trimmed);
        return NULL;
    }
    snprintf(result, 9 + strlen(host_path) + 1, "https://%s", host_path);
    free(host_path);
    free(trimmed);
    return result;
}

static char *identity_key(const portillia_identity_t *identity) {
    if (!identity) return NULL;
    char *name = identity->name ? strdup(identity->name) : strdup("");
    char *address = identity->address ? strdup(identity->address) : strdup("");
    str_trim(name);
    str_tolower_inplace(name);
    str_trim(address);
    str_tolower_inplace(address);
    size_t nlen = strlen(name);
    size_t alen = strlen(address);
    char *key = (char *)malloc(nlen + 1 + alen + 1);
    if (!key) { free(name); free(address); return NULL; }
    snprintf(key, nlen + 1 + alen + 1, "%s:%s", name, address);
    free(name);
    free(address);
    return key;
}

static char *base64_raw_url_encode(const uint8_t *data, size_t len) {
    size_t b64_len = ((len + 2) / 3) * 4;
    char *b64 = (char *)malloc(b64_len + 1);
    if (!b64) return NULL;
    int out_len = EVP_EncodeBlock((unsigned char *)b64, data, (int)len);
    if (out_len < 0) { free(b64); return NULL; }
    b64[out_len] = '\0';
    char *out = (char *)malloc(b64_len + 1);
    if (!out) { free(b64); return NULL; }
    size_t j = 0;
    for (int i = 0; i < out_len; i++) {
        if (b64[i] == '+') out[j++] = '-';
        else if (b64[i] == '/') out[j++] = '_';
        else if (b64[i] == '=') break;
        else out[j++] = b64[i];
    }
    out[j] = '\0';
    free(b64);
    return out;
}

static char *derive_hop_token(const portillia_identity_t *identity,
                              const char *public_hostname,
                              size_t hop_index,
                              const char *from_relay,
                              const char *to_relay) {
    if (!identity || !identity->private_key || !public_hostname || !from_relay || !to_relay) return NULL;
    char *key = identity_key(identity);
    if (!key) return NULL;
    unsigned char mac[SHA256_DIGEST_LENGTH];
    unsigned int mac_len = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) { free(key); return NULL; }
    if (!HMAC_Init_ex(ctx, identity->private_key, (int)strlen(identity->private_key), EVP_sha256(), NULL)) {
        HMAC_CTX_free(ctx);
        free(key);
        return NULL;
    }
    HMAC_Update(ctx, (const unsigned char *)"Portal identity token v1\n", strlen("Portal identity token v1\n"));
    HMAC_Update(ctx, (const unsigned char *)key, strlen(key));
    free(key);
    const char *parts[5] = {"hop-token", public_hostname, NULL, from_relay, to_relay};
    char idx_buf[32];
    snprintf(idx_buf, sizeof(idx_buf), "%zu", hop_index);
    parts[2] = idx_buf;
    for (int i = 0; i < 5; i++) {
        const char *part = parts[i];
        HMAC_Update(ctx, (const unsigned char *)"\n", 1);
        char len_buf[16];
        int len_n = snprintf(len_buf, sizeof(len_buf), "%zu", strlen(part));
        HMAC_Update(ctx, (const unsigned char *)len_buf, (size_t)len_n);
        HMAC_Update(ctx, (const unsigned char *)":", 1);
        HMAC_Update(ctx, (const unsigned char *)part, strlen(part));
    }
    HMAC_Final(ctx, mac, &mac_len);
    HMAC_CTX_free(ctx);
    return base64_raw_url_encode(mac, mac_len);
}

typedef struct http_buffer {
    char *data;
    size_t len;
} http_buffer_t;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    http_buffer_t *buf = (http_buffer_t *)userp;
    char *next = (char *)realloc(buf->data, buf->len + total + 1);
    if (!next) return 0;
    buf->data = next;
    memcpy(buf->data + buf->len, contents, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static void http_buffer_free(http_buffer_t *buf) {
    if (!buf) return;
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
}

static time_t parse_rfc3339_utc(const char *value) {
    if (!value || !value[0]) return 0;
    struct tm tm_utc;
    memset(&tm_utc, 0, sizeof(tm_utc));
    int year = 0, mon = 0, day = 0, hour = 0, min = 0, sec = 0;
    if (sscanf(value, "%d-%d-%dT%d:%d:%dZ", &year, &mon, &day, &hour, &min, &sec) != 6) return 0;
    tm_utc.tm_year = year - 1900;
    tm_utc.tm_mon = mon - 1;
    tm_utc.tm_mday = day;
    tm_utc.tm_hour = hour;
    tm_utc.tm_min = min;
    tm_utc.tm_sec = sec;
#if defined(__USE_BSD) || defined(__USE_GNU)
    return timegm(&tm_utc);
#else
    char *old_tz = getenv("TZ");
    char *saved = old_tz ? strdup(old_tz) : NULL;
    setenv("TZ", "UTC", 1);
    tzset();
    time_t out = mktime(&tm_utc);
    if (saved) {
        setenv("TZ", saved, 1);
        free(saved);
    } else {
        unsetenv("TZ");
    }
    tzset();
    return out;
#endif
}

static cJSON *envelope_data_or_root(cJSON *root) {
    if (!root) return NULL;
    cJSON *ok = cJSON_GetObjectItem(root, "ok");
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (ok && cJSON_IsBool(ok) && cJSON_IsTrue(ok) && data && cJSON_IsObject(data)) return data;
    if (data && cJSON_IsObject(data)) return data;
    return root;
}

static int parse_hex_bytes(const char *hex, uint8_t *out, size_t out_len) {
    const char *cur = hex;
    if (!cur || !out) return -1;
    if (cur[0] == '0' && (cur[1] == 'x' || cur[1] == 'X')) cur += 2;
    if (strlen(cur) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int v = 0;
        if (sscanf(cur + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int sign_sha256_secp256k1_der_hex(const uint8_t *payload, size_t payload_len,
                                         const char *private_key_hex, char *out_hex, size_t out_len) {
    if (!payload || !private_key_hex || !out_hex) {
        errno = EINVAL;
        return -1;
    }
    uint8_t seckey[32];
    if (parse_hex_bytes(private_key_hex, seckey, sizeof(seckey)) != 0) {
        errno = EINVAL;
        return -1;
    }

    uint8_t hash[32];
    SHA256(payload, payload_len, hash);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        errno = EIO;
        return -1;
    }

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, hash, seckey, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        errno = EIO;
        return -1;
    }

    unsigned char der[80];
    size_t der_len = sizeof(der);
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig)) {
        secp256k1_context_destroy(ctx);
        errno = EIO;
        return -1;
    }
    secp256k1_context_destroy(ctx);

    if (out_len < (der_len * 2 + 1)) {
        errno = ENOSPC;
        return -1;
    }
    for (size_t i = 0; i < der_len; i++) {
        sprintf(out_hex + i * 2, "%02x", der[i]);
    }
    out_hex[der_len * 2] = '\0';
    return 0;
}

static void json_add_time_unix_nano(cJSON *obj, const char *key, time_t value) {
    double nanos = (double)value * 1000000000.0;
    cJSON_AddNumberToObject(obj, key, nanos);
}

static cJSON *relay_descriptor_to_canonical_json(const portillia_relay_descriptor_t *desc, bool include_overlay_ipv4) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "address", desc && desc->address ? desc->address : "");
    cJSON_AddStringToObject(obj, "version", desc && desc->version ? desc->version : "");
    json_add_time_unix_nano(obj, "issued_at_unix_nano", desc ? desc->issued_at : 0);
    json_add_time_unix_nano(obj, "expires_at_unix_nano", desc ? desc->expires_at : 0);
    cJSON_AddStringToObject(obj, "api_https_addr", desc && desc->api_https_addr ? desc->api_https_addr : "");
    cJSON_AddStringToObject(obj, "wireguard_public_key", desc && desc->wireguard_public_key ? desc->wireguard_public_key : "");
    cJSON_AddNumberToObject(obj, "wireguard_port", desc ? desc->wireguard_port : 0);
    cJSON_AddBoolToObject(obj, "supports_overlay", desc ? desc->supports_overlay : false);
    cJSON_AddBoolToObject(obj, "supports_udp", desc ? desc->supports_udp : false);
    cJSON_AddBoolToObject(obj, "supports_tcp", desc ? desc->supports_tcp : false);
    cJSON_AddNumberToObject(obj, "active_connections", desc ? (double)desc->active_connections : 0.0);
    cJSON_AddNumberToObject(obj, "tcp_bps", desc ? desc->tcp_bps : 0.0);
    if (include_overlay_ipv4 && desc && desc->wireguard_public_key && desc->wireguard_public_key[0]) {
        char overlay_ipv4[32] = {0};
        if (portillia_crypto_derive_overlay_ipv4(desc->wireguard_public_key, overlay_ipv4) == 0) {
            cJSON_AddStringToObject(obj, "wireguard_ipv4", overlay_ipv4);
        }
    }
    return obj;
}

static int build_hop_route_payload(const char *method, const portillia_hop_route_t *route, char **out_json) {
    if (!method || !route || !out_json) {
        errno = EINVAL;
        return -1;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "purpose", "portal hop route v1");

    char upper_method[16] = {0};
    size_t mlen = strlen(method);
    if (mlen >= sizeof(upper_method)) mlen = sizeof(upper_method) - 1;
    for (size_t i = 0; i < mlen; i++) upper_method[i] = (char)toupper((unsigned char)method[i]);
    cJSON_AddStringToObject(root, "method", upper_method);

    cJSON_AddStringToObject(root, "owner_public_key", route->owner_public_key ? route->owner_public_key : "");
    cJSON_AddStringToObject(root, "relay_url", route->relay_url ? route->relay_url : "");
    cJSON_AddStringToObject(root, "match_hostname", route->match_hostname ? route->match_hostname : "");
    cJSON_AddStringToObject(root, "match_token", route->match_token ? route->match_token : "");
    cJSON_AddItemToObject(root, "forward_relay", relay_descriptor_to_canonical_json(&route->forward_relay, false));
    cJSON_AddStringToObject(root, "forward_token", route->forward_token ? route->forward_token : "");
    json_add_time_unix_nano(root, "first_seen_at_unix_nano", route->first_seen_at);
    json_add_time_unix_nano(root, "expires_at_unix_nano", route->expires_at);

    *out_json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!*out_json) {
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

static int sign_hop_route(const char *method, portillia_hop_route_t *route, const portillia_identity_t *identity, time_t expires_at) {
    if (!method || !route || !identity || !identity->private_key || !identity->public_key) {
        errno = EINVAL;
        return -1;
    }
    if (route->owner_public_key) portillia_gc_free_later(route->owner_public_key);
    if (route->signature) portillia_gc_free_later(route->signature);

    /* Normalize owner public key: trim, strip 0x, lowercase */
    char *pk = trim_hex_prefix(identity->public_key);
    if (pk) {
        str_trim(pk);
        str_tolower_inplace(pk);
    }
    route->owner_public_key = portillia_gc_strdup(pk && pk[0] ? pk : identity->public_key);
    free(pk);

    /* Normalize relay url */
    if (route->relay_url) {
        char *norm = normalize_relay_url(route->relay_url);
        if (norm) {
            portillia_gc_free_later(route->relay_url);
            route->relay_url = portillia_gc_strdup(norm);
            free(norm);
        }
    }

    /* Normalize match_hostname */
    if (route->match_hostname) {
        char *norm = normalize_hostname(route->match_hostname);
        if (norm) {
            portillia_gc_free_later(route->match_hostname);
            route->match_hostname = portillia_gc_strdup(norm);
            free(norm);
        }
    }

    /* Trim tokens */
    if (route->match_token) {
        char *tmp = strdup(route->match_token);
        str_trim(tmp);
        if (strcmp(tmp, route->match_token) != 0) {
            portillia_gc_free_later(route->match_token);
            route->match_token = portillia_gc_strdup(tmp);
        }
        free(tmp);
    }
    if (route->forward_token) {
        char *tmp = strdup(route->forward_token);
        str_trim(tmp);
        if (strcmp(tmp, route->forward_token) != 0) {
            portillia_gc_free_later(route->forward_token);
            route->forward_token = portillia_gc_strdup(tmp);
        }
        free(tmp);
    }

    route->expires_at = expires_at;

    char *payload_json = NULL;
    if (build_hop_route_payload(method, route, &payload_json) != 0) return -1;

    char sig_hex[200];
    int rc = sign_sha256_secp256k1_der_hex((const uint8_t *)payload_json, strlen(payload_json), identity->private_key, sig_hex, sizeof(sig_hex));
    free(payload_json);
    if (rc != 0) return -1;

    route->signature = portillia_gc_strdup(sig_hex);
    return 0;
}

static cJSON *hop_route_to_request_json(const portillia_hop_route_t *route, const portillia_identity_t *identity) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "owner_public_key", route->owner_public_key ? route->owner_public_key : "");
    cJSON_AddStringToObject(root, "relay_url", route->relay_url ? route->relay_url : "");
    if (route->match_hostname && route->match_hostname[0]) cJSON_AddStringToObject(root, "match_hostname", route->match_hostname);
    if (route->match_token && route->match_token[0]) cJSON_AddStringToObject(root, "match_token", route->match_token);
    if (route->forward_token && route->forward_token[0]) cJSON_AddStringToObject(root, "forward_token", route->forward_token);
    if (route->signature && route->signature[0]) cJSON_AddStringToObject(root, "signature", route->signature);
    if (identity && identity->address) cJSON_AddStringToObject(root, "identity", identity->address);
    if (route->metadata.description || route->metadata.owner || route->metadata.thumbnail || route->metadata.hide || route->metadata.tags_count > 0) {
        cJSON *meta = cJSON_CreateObject();
        if (route->metadata.description) cJSON_AddStringToObject(meta, "description", route->metadata.description);
        if (route->metadata.owner) cJSON_AddStringToObject(meta, "owner", route->metadata.owner);
        if (route->metadata.thumbnail) cJSON_AddStringToObject(meta, "thumbnail", route->metadata.thumbnail);
        if (route->metadata.tags && route->metadata.tags_count > 0) {
            cJSON *tags = cJSON_CreateArray();
            for (size_t i = 0; i < route->metadata.tags_count; i++) {
                cJSON_AddItemToArray(tags, cJSON_CreateString(route->metadata.tags[i] ? route->metadata.tags[i] : ""));
            }
            cJSON_AddItemToObject(meta, "tags", tags);
        }
        cJSON_AddBoolToObject(meta, "hide", route->metadata.hide);
        cJSON_AddItemToObject(root, "metadata", meta);
    }
    cJSON_AddItemToObject(root, "forward_relay", relay_descriptor_to_canonical_json(&route->forward_relay, true));
    return root;
}

static int http_json(portillia_http_client_t *client,
                     const char *base_url,
                     const char *method,
                     const char *path,
                     const char *body,
                     struct curl_slist *extra_headers,
                     long *out_status,
                     cJSON **out_json) {
    if (!client || !method || !path) {
        errno = EINVAL;
        return -1;
    }

    if (!client->curl) {
        client->curl = curl_easy_init();
        if (!client->curl) {
            errno = EIO;
            return -1;
        }
    }

    CURL *curl = client->curl;
    http_buffer_t buf = {0};
    char url[2048];
    snprintf(url, sizeof(url), "%s%s", base_url ? base_url : client->relay_url, path);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    if (strcmp(method, "POST") == 0 || strcmp(method, "DELETE") == 0) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }
    for (struct curl_slist *cur = extra_headers; cur; cur = cur->next) {
        headers = curl_slist_append(headers, cur->data);
    }

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "portillia-c-sdk/1");
    if (strncmp(url, "https://", 8) == 0) {
        portillia_network_configure_curl_tls(curl, client->insecure_skip_verify);
    }

    if (strcmp(method, "GET") == 0) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    } else {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    }

    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);

    if (rc != CURLE_OK) {
        http_buffer_free(&buf);
        errno = EIO;
        return -1;
    }

    if (out_status) *out_status = status;
    if (out_json) {
        *out_json = NULL;
        if (buf.data && buf.data[0]) *out_json = cJSON_Parse(buf.data);
    }

    if (status >= 400) {
        http_buffer_free(&buf);
        errno = EACCES;
        return -1;
    }

    http_buffer_free(&buf);
    return 0;
}

static int parse_domain_response_json(cJSON *root, portillia_domain_response_t *out) {
    cJSON *data = envelope_data_or_root(root);
    cJSON *protocol_version = data ? cJSON_GetObjectItem(data, "protocol_version") : NULL;
    cJSON *sdk_version = data ? cJSON_GetObjectItem(data, "sdk_version") : NULL;
    cJSON *discovery_version = data ? cJSON_GetObjectItem(data, "discovery_version") : NULL;
    cJSON *release_version = data ? cJSON_GetObjectItem(data, "release_version") : NULL;

    memset(out, 0, sizeof(*out));
    if (protocol_version && cJSON_IsString(protocol_version) && protocol_version->valuestring) {
        out->protocol_version = portillia_gc_strdup(protocol_version->valuestring);
    }
    if (sdk_version && cJSON_IsString(sdk_version) && sdk_version->valuestring) {
        out->sdk_version = portillia_gc_strdup(sdk_version->valuestring);
    } else if (release_version && cJSON_IsString(release_version) && release_version->valuestring) {
        out->sdk_version = portillia_gc_strdup(release_version->valuestring);
    }
    if (discovery_version && cJSON_IsString(discovery_version) && discovery_version->valuestring) {
        out->discovery_version = portillia_gc_strdup(discovery_version->valuestring);
    }
    return out->protocol_version ? 0 : -1;
}

static int parse_register_challenge_response_json(cJSON *root, portillia_register_challenge_response_t *out) {
    cJSON *data = envelope_data_or_root(root);
    cJSON *challenge_id = data ? cJSON_GetObjectItem(data, "challenge_id") : NULL;
    cJSON *expires_at = data ? cJSON_GetObjectItem(data, "expires_at") : NULL;
    cJSON *siwe_message = data ? cJSON_GetObjectItem(data, "siwe_message") : NULL;
    memset(out, 0, sizeof(*out));
    if (challenge_id && cJSON_IsString(challenge_id) && challenge_id->valuestring) {
        out->challenge_id = portillia_gc_strdup(challenge_id->valuestring);
    }
    if (siwe_message && cJSON_IsString(siwe_message) && siwe_message->valuestring) {
        out->siwe_message = portillia_gc_strdup(siwe_message->valuestring);
    }
    if (expires_at && cJSON_IsString(expires_at) && expires_at->valuestring) {
        out->expires_at = parse_rfc3339_utc(expires_at->valuestring);
    }
    return (out->challenge_id && out->siwe_message) ? 0 : -1;
}

static int parse_register_response_json(cJSON *root, portillia_register_response_t *out) {
    cJSON *data = envelope_data_or_root(root);
    cJSON *expires_at = data ? cJSON_GetObjectItem(data, "expires_at") : NULL;
    cJSON *hostname = data ? cJSON_GetObjectItem(data, "hostname") : NULL;
    cJSON *access_token = data ? cJSON_GetObjectItem(data, "access_token") : NULL;
    cJSON *keyless_url = data ? cJSON_GetObjectItem(data, "keyless_url") : NULL;
    cJSON *sni_port = data ? cJSON_GetObjectItem(data, "sni_port") : NULL;
    cJSON *udp_addr = data ? cJSON_GetObjectItem(data, "udp_addr") : NULL;
    cJSON *udp_enabled = data ? cJSON_GetObjectItem(data, "udp_enabled") : NULL;
    cJSON *tcp_addr = data ? cJSON_GetObjectItem(data, "tcp_addr") : NULL;
    cJSON *tcp_enabled = data ? cJSON_GetObjectItem(data, "tcp_enabled") : NULL;
    cJSON *identity = data ? cJSON_GetObjectItem(data, "identity") : NULL;
    cJSON *name = identity ? cJSON_GetObjectItem(identity, "name") : NULL;
    cJSON *address = identity ? cJSON_GetObjectItem(identity, "address") : NULL;

    memset(out, 0, sizeof(*out));
    if (name && cJSON_IsString(name) && name->valuestring) out->identity.name = portillia_gc_strdup(name->valuestring);
    if (address && cJSON_IsString(address) && address->valuestring) out->identity.address = portillia_gc_strdup(address->valuestring);
    if (hostname && cJSON_IsString(hostname) && hostname->valuestring) out->hostname = portillia_gc_strdup(hostname->valuestring);
    if (access_token && cJSON_IsString(access_token) && access_token->valuestring) out->access_token = portillia_gc_strdup(access_token->valuestring);
    if (keyless_url && cJSON_IsString(keyless_url) && keyless_url->valuestring) out->keyless_url = portillia_gc_strdup(keyless_url->valuestring);
    if (udp_addr && cJSON_IsString(udp_addr) && udp_addr->valuestring) out->udp_addr = portillia_gc_strdup(udp_addr->valuestring);
    if (tcp_addr && cJSON_IsString(tcp_addr) && tcp_addr->valuestring) out->tcp_addr = portillia_gc_strdup(tcp_addr->valuestring);
    if (expires_at && cJSON_IsString(expires_at) && expires_at->valuestring) out->expires_at = parse_rfc3339_utc(expires_at->valuestring);
    if (sni_port && cJSON_IsNumber(sni_port)) out->sni_port = sni_port->valueint;
    out->udp_enabled = udp_enabled ? cJSON_IsTrue(udp_enabled) : false;
    out->tcp_enabled = tcp_enabled ? cJSON_IsTrue(tcp_enabled) : false;
    return (out->hostname && out->access_token) ? 0 : -1;
}

static int parse_renew_response_json(cJSON *root, portillia_renew_response_t *out) {
    cJSON *data = envelope_data_or_root(root);
    cJSON *expires_at = data ? cJSON_GetObjectItem(data, "expires_at") : NULL;
    cJSON *access_token = data ? cJSON_GetObjectItem(data, "access_token") : NULL;
    memset(out, 0, sizeof(*out));
    if (access_token && cJSON_IsString(access_token) && access_token->valuestring) {
        out->access_token = portillia_gc_strdup(access_token->valuestring);
    }
    if (expires_at && cJSON_IsString(expires_at) && expires_at->valuestring) {
        out->expires_at = parse_rfc3339_utc(expires_at->valuestring);
    }
    return out->access_token ? 0 : -1;
}

portillia_http_client_t *portillia_http_client_create(const char *relay_url,
                                                      bool insecure_skip_verify) {
    if (!relay_url) return NULL;
    static bool curl_inited = false;
    if (!curl_inited) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_inited = true;
    }
    portillia_http_client_t *c = PORTILLIA_GC_NEW_ZERO(portillia_http_client_t);
    if (!c) return NULL;
    c->relay_url = portillia_gc_strdup(relay_url);
    c->curl = curl_easy_init();
    c->insecure_skip_verify = insecure_skip_verify;
    return c;
}

void portillia_http_client_destroy(portillia_http_client_t *client) {
    if (!client) return;
    if (client->curl) curl_easy_cleanup(client->curl);
    if (client->relay_url) portillia_gc_free_later(client->relay_url);
    portillia_gc_free_later(client);
}

void portillia_http_client_close_idle(portillia_http_client_t *client) {
    if (!client || !client->curl) return;
    curl_easy_reset(client->curl);
}

int portillia_http_client_check_domain(portillia_http_client_t *client) {
    if (!client) {
        errno = EINVAL;
        return -1;
    }
    long status = 0;
    cJSON *root = NULL;
    portillia_domain_response_t resp = {0};
    int rc = http_json(client, NULL, "GET", SDK_PATH_DOMAIN, NULL, NULL, &status, &root);
    if (rc != 0) {
        cJSON_Delete(root);
        return -1;
    }
    rc = parse_domain_response_json(root, &resp);
    cJSON_Delete(root);
    if (rc != 0 || !resp.protocol_version || strcmp(resp.protocol_version, PORTILLIA_SDK_VERSION) != 0) {
        if (resp.protocol_version) portillia_gc_free_later(resp.protocol_version);
        if (resp.sdk_version) portillia_gc_free_later(resp.sdk_version);
        if (resp.discovery_version) portillia_gc_free_later(resp.discovery_version);
        errno = EPROTO;
        return -1;
    }
    if (resp.protocol_version) portillia_gc_free_later(resp.protocol_version);
    if (resp.sdk_version) portillia_gc_free_later(resp.sdk_version);
    if (resp.discovery_version) portillia_gc_free_later(resp.discovery_version);
    return 0;
}

int portillia_api_register_lease(portillia_http_client_t *client,
                                 const portillia_identity_t *identity,
                                 const portillia_lease_metadata_t *metadata,
                                 portillia_relay_set_t *relay_set,
                                 const char **multi_hop, size_t multi_hop_count,
                                 int ttl_sec, bool udp_enabled, bool tcp_enabled,
                                 portillia_register_response_t *out_resp,
                                 portillia_hop_route_t **out_hops, size_t *out_hop_count) {
    if (!client || !identity || !out_resp) {
        errno = EINVAL;
        return -1;
    }

    if (out_hops) *out_hops = NULL;
    if (out_hop_count) *out_hop_count = 0;
    memset(out_resp, 0, sizeof(*out_resp));

    char *public_hostname = NULL;
    char *keyless_url = NULL;
    char *exit_hop_token = NULL;
    portillia_hop_route_t *hop_routes = NULL;
    size_t hop_routes_count = 0;

    if (multi_hop_count > 0) {
        if (!multi_hop || multi_hop_count < 2 || !relay_set || !identity->name) {
            errno = EINVAL;
            return -1;
        }

        portillia_relay_descriptor_t *path = (portillia_relay_descriptor_t *)calloc(multi_hop_count, sizeof(*path));
        if (!path) {
            errno = ENOMEM;
            return -1;
        }
        time_t now = time(NULL);
        for (size_t i = 0; i < multi_hop_count; i++) {
            portillia_relay_descriptor_init(&path[i]);
            if (!portillia_relay_set_overlay_descriptor(relay_set, multi_hop[i], now, &path[i])) {
                for (size_t j = 0; j <= i; j++) portillia_relay_descriptor_cleanup(&path[j]);
                free(path);
                errno = ENOENT;
                return -1;
            }
        }

        const char *entry_url_raw = path[0].api_https_addr ? path[0].api_https_addr : multi_hop[0];
        char *norm_entry = normalize_relay_url(entry_url_raw);
        if (!norm_entry) {
            for (size_t i = 0; i < multi_hop_count; i++) portillia_relay_descriptor_cleanup(&path[i]);
            free(path);
            errno = EINVAL;
            return -1;
        }
        const char *host_start = strstr(norm_entry, "://");
        host_start = host_start ? host_start + 3 : norm_entry;
        const char *host_end = strchr(host_start, '/');
        size_t host_len = host_end ? (size_t)(host_end - host_start) : strlen(host_start);
        const char *colon = memchr(host_start, ':', host_len);
        if (colon) host_len = (size_t)(colon - host_start);

        char *label = normalize_dns_label(identity->name);
        if (!label) {
            free(norm_entry);
            for (size_t i = 0; i < multi_hop_count; i++) portillia_relay_descriptor_cleanup(&path[i]);
            free(path);
            errno = EINVAL;
            return -1;
        }
        char *root_host = (char *)malloc(host_len + 1);
        if (!root_host) {
            free(label);
            free(norm_entry);
            for (size_t i = 0; i < multi_hop_count; i++) portillia_relay_descriptor_cleanup(&path[i]);
            free(path);
            errno = ENOMEM;
            return -1;
        }
        memcpy(root_host, host_start, host_len);
        root_host[host_len] = '\0';
        char *norm_root = normalize_hostname(root_host);
        free(root_host);
        public_hostname = (char *)malloc(strlen(label) + 1 + strlen(norm_root) + 1);
        if (!public_hostname) {
            free(label);
            free(norm_root);
            free(norm_entry);
            for (size_t i = 0; i < multi_hop_count; i++) portillia_relay_descriptor_cleanup(&path[i]);
            free(path);
            errno = ENOMEM;
            return -1;
        }
        snprintf(public_hostname, strlen(label) + 1 + strlen(norm_root) + 1, "%s.%s", label, norm_root);
        free(label);
        free(norm_root);
        keyless_url = strdup(norm_entry);
        free(norm_entry);

        hop_routes_count = multi_hop_count - 1;
        hop_routes = (portillia_hop_route_t *)portillia_gc_alloc(sizeof(*hop_routes) * hop_routes_count);
        if (!hop_routes) {
            for (size_t i = 0; i < multi_hop_count; i++) portillia_relay_descriptor_cleanup(&path[i]);
            free(path);
            free(public_hostname);
            free(keyless_url);
            errno = ENOMEM;
            return -1;
        }
        memset(hop_routes, 0, sizeof(*hop_routes) * hop_routes_count);

        char *previous_token = NULL;
        for (size_t i = 0; i < hop_routes_count; i++) {
            char *derived = derive_hop_token(identity, public_hostname, i,
                                             path[i].api_https_addr ? path[i].api_https_addr : multi_hop[i],
                                             path[i + 1].api_https_addr ? path[i + 1].api_https_addr : multi_hop[i + 1]);
            char forward_token[256];
            snprintf(forward_token, sizeof(forward_token), "hpt_%s", derived ? derived : "");
            free(derived);

            char *norm_relay = normalize_relay_url(path[i].api_https_addr ? path[i].api_https_addr : multi_hop[i]);
            hop_routes[i].relay_url = portillia_gc_strdup(norm_relay ? norm_relay : "");
            free(norm_relay);

            portillia_relay_descriptor_copy(&hop_routes[i].forward_relay, &path[i + 1]);
            hop_routes[i].forward_token = portillia_gc_strdup(forward_token);
            if (i == 0) {
                hop_routes[i].match_hostname = portillia_gc_strdup(public_hostname);
                if (metadata) portillia_lease_metadata_copy(&hop_routes[i].metadata, metadata);
            } else if (previous_token) {
                hop_routes[i].match_token = portillia_gc_strdup(previous_token);
            }
            free(previous_token);
            previous_token = strdup(forward_token);
        }
        exit_hop_token = previous_token;
        for (size_t i = 0; i < multi_hop_count; i++) portillia_relay_descriptor_cleanup(&path[i]);
        free(path);
    }

    char derived_address[43] = {0};
    const char *identity_address = identity->address ? identity->address : "";
    if (identity->private_key &&
        portillia_crypto_derive_address_from_private_key(identity->private_key, derived_address, sizeof(derived_address)) == 0) {
        if (identity->address && identity->address[0] && strcasecmp(identity->address, derived_address) != 0) {
            LOG_WARN("SDK: Identity address %s does not match signing key; using derived address %s for SIWE",
                     identity->address, derived_address);
        }
        identity_address = derived_address;
    }

    cJSON *challenge_req = cJSON_CreateObject();
    cJSON *identity_json = cJSON_CreateObject();
    cJSON_AddStringToObject(identity_json, "name", identity->name ? identity->name : "");
    cJSON_AddStringToObject(identity_json, "address", identity_address);
    cJSON_AddItemToObject(challenge_req, "identity", identity_json);
    if (metadata) {
        cJSON *meta = cJSON_CreateObject();
        if (metadata->description) cJSON_AddStringToObject(meta, "description", metadata->description);
        if (metadata->owner) cJSON_AddStringToObject(meta, "owner", metadata->owner);
        if (metadata->thumbnail) cJSON_AddStringToObject(meta, "thumbnail", metadata->thumbnail);
        if (metadata->tags && metadata->tags_count > 0) {
            cJSON *tags = cJSON_CreateArray();
            for (size_t i = 0; i < metadata->tags_count; i++) {
                cJSON_AddItemToArray(tags, cJSON_CreateString(metadata->tags[i] ? metadata->tags[i] : ""));
            }
            cJSON_AddItemToObject(meta, "tags", tags);
        }
        cJSON_AddBoolToObject(meta, "hide", metadata->hide);
        cJSON_AddItemToObject(challenge_req, "metadata", meta);
    }
    cJSON_AddNumberToObject(challenge_req, "ttl", ttl_sec);
    cJSON_AddBoolToObject(challenge_req, "udp_enabled", udp_enabled);
    cJSON_AddBoolToObject(challenge_req, "tcp_enabled", tcp_enabled);
    if (exit_hop_token) cJSON_AddStringToObject(challenge_req, "hop_token", exit_hop_token);
    char *challenge_body = cJSON_PrintUnformatted(challenge_req);
    cJSON_Delete(challenge_req);
    if (!challenge_body) {
        errno = ENOMEM;
        return -1;
    }

    long status = 0;
    cJSON *root = NULL;
    portillia_register_challenge_response_t challenge = {0};
    int rc = http_json(client, NULL, "POST", SDK_PATH_REGISTER_CHALLENGE, challenge_body, NULL, &status, &root);
    free(challenge_body);
    if (rc != 0) {
        cJSON_Delete(root);
        return -1;
    }
    rc = parse_register_challenge_response_json(root, &challenge);
    cJSON_Delete(root);
    if (rc != 0) {
        errno = EBADMSG;
        return -1;
    }

    char signature[133];
    if (portillia_crypto_sign_siwe_message(challenge.siwe_message, identity->private_key, signature, sizeof(signature)) != 0) {
        portillia_gc_free_later(challenge.challenge_id);
        portillia_gc_free_later(challenge.siwe_message);
        return -1;
    }

    cJSON *register_req = cJSON_CreateObject();
    cJSON_AddStringToObject(register_req, "challenge_id", challenge.challenge_id);
    cJSON_AddStringToObject(register_req, "siwe_message", challenge.siwe_message);
    cJSON_AddStringToObject(register_req, "siwe_signature", signature);
    char *register_body = cJSON_PrintUnformatted(register_req);
    cJSON_Delete(register_req);
    if (!register_body) {
        portillia_gc_free_later(challenge.challenge_id);
        portillia_gc_free_later(challenge.siwe_message);
        errno = ENOMEM;
        return -1;
    }

    root = NULL;
    rc = http_json(client, NULL, "POST", SDK_PATH_REGISTER, register_body, NULL, &status, &root);
    free(register_body);
    portillia_gc_free_later(challenge.challenge_id);
    portillia_gc_free_later(challenge.siwe_message);
    if (rc != 0) {
        cJSON_Delete(root);
        return -1;
    }
    rc = parse_register_response_json(root, out_resp);
    cJSON_Delete(root);
    if (rc != 0) {
        errno = EBADMSG;
        return -1;
    }
    if (hop_routes_count > 0) {
        if (portillia_api_sync_hop_routes(client, "POST", out_resp->expires_at, identity, relay_set, hop_routes, hop_routes_count) != 0) {
            portillia_api_unregister_lease(client, out_resp->access_token, hop_routes, hop_routes_count);
            errno = EIO;
            return -1;
        }
        if (out_resp->hostname) portillia_gc_free_later(out_resp->hostname);
        if (out_resp->keyless_url) portillia_gc_free_later(out_resp->keyless_url);
        out_resp->hostname = portillia_gc_strdup(public_hostname);
        out_resp->keyless_url = keyless_url ? portillia_gc_strdup(keyless_url) : NULL;
        if (out_hops) *out_hops = hop_routes;
        if (out_hop_count) *out_hop_count = hop_routes_count;
    }
    free(public_hostname);
    free(keyless_url);
    free(exit_hop_token);
    return 0;
}

int portillia_api_renew_lease(portillia_http_client_t *client,
                              int ttl_sec,
                              const char *access_token,
                              const portillia_identity_t *identity,
                              portillia_relay_set_t *relay_set,
                              portillia_hop_route_t *hops, size_t hop_count,
                              portillia_renew_response_t *out_resp) {
    if (!client || !access_token || !out_resp) {
        errno = EINVAL;
        return -1;
    }
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "access_token", access_token);
    cJSON_AddNumberToObject(req, "ttl", ttl_sec);
    char *body = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!body) {
        errno = ENOMEM;
        return -1;
    }

    long status = 0;
    cJSON *root = NULL;
    int rc = http_json(client, NULL, "POST", SDK_PATH_RENEW, body, NULL, &status, &root);
    free(body);
    if (rc != 0) {
        cJSON_Delete(root);
        return -1;
    }
    rc = parse_renew_response_json(root, out_resp);
    cJSON_Delete(root);
    if (rc != 0) {
        errno = EBADMSG;
        return -1;
    }
    if (hop_count > 0 && hops) {
        if (portillia_api_sync_hop_routes(client, "POST", out_resp->expires_at, identity, relay_set, hops, hop_count) != 0) {
            return -1;
        }
    }
    return 0;
}

int portillia_api_unregister_lease(portillia_http_client_t *client,
                                   const char *access_token,
                                   portillia_hop_route_t *hops, size_t hop_count) {
    if (!client || !access_token) {
        errno = EINVAL;
        return -1;
    }
    if (hop_count > 0 && hops) {
        (void)portillia_api_sync_hop_routes(client, "DELETE", 0, NULL, NULL, hops, hop_count);
    }

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "access_token", access_token);
    char *body = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!body) {
        errno = ENOMEM;
        return -1;
    }

    long status = 0;
    cJSON *root = NULL;
    int rc = http_json(client, NULL, "POST", SDK_PATH_UNREGISTER, body, NULL, &status, &root);
    free(body);
    cJSON_Delete(root);
    return rc;
}

int portillia_api_sync_hop_routes(portillia_http_client_t *client,
                                  const char *method,
                                  time_t expires_at,
                                  const portillia_identity_t *identity,
                                  portillia_relay_set_t *relay_set,
                                  portillia_hop_route_t *hops, size_t hop_count) {
    if (!client || !method || !hops || hop_count == 0) {
        if (hop_count == 0) return 0;
        errno = EINVAL;
        return -1;
    }

    bool is_post = strcmp(method, "POST") == 0;
    portillia_hop_route_t *ordered = hops;
    if (is_post) {
        if (!identity || !relay_set) {
            errno = EINVAL;
            return -1;
        }
        ordered = (portillia_hop_route_t *)calloc(hop_count, sizeof(*ordered));
        if (!ordered) {
            errno = ENOMEM;
            return -1;
        }
        time_t now = time(NULL);
        for (size_t i = 0; i < hop_count; i++) {
            portillia_hop_route_copy(&ordered[i], &hops[hop_count - 1 - i]);
            portillia_relay_descriptor_cleanup(&ordered[i].forward_relay);
            portillia_relay_descriptor_init(&ordered[i].forward_relay);
            if (!portillia_relay_set_overlay_descriptor(relay_set, hops[hop_count - 1 - i].forward_relay.api_https_addr, now, &ordered[i].forward_relay)) {
                for (size_t j = 0; j <= i; j++) portillia_hop_route_cleanup(&ordered[j]);
                free(ordered);
                errno = ENOENT;
                return -1;
            }
        }
    }

    int rc = 0;
    for (size_t i = 0; i < hop_count; i++) {
        portillia_hop_route_t route;
        portillia_hop_route_init(&route);
        portillia_hop_route_copy(&route, &ordered[i]);
        route.first_seen_at = is_post ? (expires_at - 30) : 0;
        if (is_post && sign_hop_route(method, &route, identity, expires_at) != 0) {
            rc = -1;
            portillia_hop_route_cleanup(&route);
            if (!is_post) continue;
            break;
        }

        cJSON *req = hop_route_to_request_json(&route, identity);
        char *body = cJSON_PrintUnformatted(req);
        cJSON_Delete(req);
        if (!body) {
            portillia_hop_route_cleanup(&route);
            rc = -1;
            errno = ENOMEM;
            break;
        }

        long status = 0;
        cJSON *root = NULL;
        int req_rc = http_json(client, route.relay_url, method, SDK_PATH_HOP, body, NULL, &status, &root);
        free(body);
        cJSON_Delete(root);
        portillia_hop_route_cleanup(&route);
        if (req_rc != 0) {
            rc = -1;
            if (!is_post) continue;
            break;
        }
    }

    if (is_post && ordered != hops) {
        for (size_t i = 0; i < hop_count; i++) portillia_hop_route_cleanup(&ordered[i]);
        free(ordered);
    }
    return rc;
}

/* ---------- Discovery API ---------- */

static int parse_relay_descriptor_json(cJSON *obj, portillia_relay_descriptor_t *out) {
    if (!obj || !out) return -1;
    memset(out, 0, sizeof(*out));

    cJSON *address = cJSON_GetObjectItem(obj, "address");
    cJSON *version = cJSON_GetObjectItem(obj, "version");
    cJSON *issued_at = cJSON_GetObjectItem(obj, "issued_at");
    cJSON *expires_at = cJSON_GetObjectItem(obj, "expires_at");
    cJSON *api_https_addr = cJSON_GetObjectItem(obj, "api_https_addr");
    cJSON *wireguard_public_key = cJSON_GetObjectItem(obj, "wireguard_public_key");
    cJSON *wireguard_port = cJSON_GetObjectItem(obj, "wireguard_port");
    cJSON *supports_overlay = cJSON_GetObjectItem(obj, "supports_overlay");
    cJSON *supports_udp = cJSON_GetObjectItem(obj, "supports_udp");
    cJSON *supports_tcp = cJSON_GetObjectItem(obj, "supports_tcp");
    cJSON *active_connections = cJSON_GetObjectItem(obj, "active_connections");
    cJSON *tcp_bps = cJSON_GetObjectItem(obj, "tcp_bps");
    cJSON *signature = cJSON_GetObjectItem(obj, "signature");

    if (address && cJSON_IsString(address) && address->valuestring)
        out->address = portillia_gc_strdup(address->valuestring);
    if (version && cJSON_IsString(version) && version->valuestring)
        out->version = portillia_gc_strdup(version->valuestring);
    if (issued_at && cJSON_IsString(issued_at) && issued_at->valuestring)
        out->issued_at = parse_rfc3339_utc(issued_at->valuestring);
    if (expires_at && cJSON_IsString(expires_at) && expires_at->valuestring)
        out->expires_at = parse_rfc3339_utc(expires_at->valuestring);
    if (api_https_addr && cJSON_IsString(api_https_addr) && api_https_addr->valuestring)
        out->api_https_addr = portillia_gc_strdup(api_https_addr->valuestring);
    if (wireguard_public_key && cJSON_IsString(wireguard_public_key) && wireguard_public_key->valuestring)
        out->wireguard_public_key = portillia_gc_strdup(wireguard_public_key->valuestring);
    if (wireguard_port && cJSON_IsNumber(wireguard_port))
        out->wireguard_port = wireguard_port->valueint;
    if (supports_overlay && cJSON_IsBool(supports_overlay))
        out->supports_overlay = cJSON_IsTrue(supports_overlay);
    if (supports_udp && cJSON_IsBool(supports_udp))
        out->supports_udp = cJSON_IsTrue(supports_udp);
    if (supports_tcp && cJSON_IsBool(supports_tcp))
        out->supports_tcp = cJSON_IsTrue(supports_tcp);
    if (active_connections && cJSON_IsNumber(active_connections))
        out->active_connections = (int64_t)active_connections->valuedouble;
    if (tcp_bps && cJSON_IsNumber(tcp_bps))
        out->tcp_bps = tcp_bps->valuedouble;
    if (signature && cJSON_IsString(signature) && signature->valuestring)
        out->signature = portillia_gc_strdup(signature->valuestring);

    return 0;
}

int portillia_api_discover_relays(portillia_http_client_t *client, portillia_discovery_response_t *out_resp) {
    if (!client || !out_resp) {
        errno = EINVAL;
        return -1;
    }
    portillia_discovery_response_init(out_resp);

    long status = 0;
    cJSON *root = NULL;
    int rc = http_json(client, NULL, "GET", SDK_PATH_DISCOVERY, NULL, NULL, &status, &root);
    if (rc != 0) {
        if (root) cJSON_Delete(root);
        return -1;
    }

    cJSON *data = envelope_data_or_root(root);
    cJSON *protocol_version = data ? cJSON_GetObjectItem(data, "protocol_version") : NULL;
    cJSON *generated_at = data ? cJSON_GetObjectItem(data, "generated_at") : NULL;
    cJSON *relays = data ? cJSON_GetObjectItem(data, "relays") : NULL;

    if (protocol_version && cJSON_IsString(protocol_version) && protocol_version->valuestring) {
        out_resp->protocol_version = portillia_gc_strdup(protocol_version->valuestring);
    }
    if (generated_at && cJSON_IsString(generated_at) && generated_at->valuestring) {
        out_resp->generated_at = parse_rfc3339_utc(generated_at->valuestring);
    }

    if (relays && cJSON_IsArray(relays)) {
        int n = cJSON_GetArraySize(relays);
        if (n > 0) {
            out_resp->relays = (portillia_relay_descriptor_t *)portillia_gc_alloc(sizeof(portillia_relay_descriptor_t) * (size_t)n);
            if (!out_resp->relays) {
                cJSON_Delete(root);
                errno = ENOMEM;
                return -1;
            }
            int valid = 0;
            for (int i = 0; i < n; i++) {
                cJSON *item = cJSON_GetArrayItem(relays, i);
                if (!item) continue;
                if (parse_relay_descriptor_json(item, &out_resp->relays[valid]) == 0) {
                    valid++;
                }
            }
            out_resp->relays_count = (size_t)valid;
        }
    }

    cJSON_Delete(root);
    return 0;
}
