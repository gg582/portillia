#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <cwist/core/utils/json_builder.h>
#include <portillia/portal/discovery/discovery.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/utils/crypto.h>
#include <portillia/portal/settings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <time.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

extern void portillia_registry_register(const char *hostname, const char *identity_key, int64_t bps_limit);
extern void portillia_registry_register_hop(const char *hop_token, const char *next_ipv4, const char *next_token, const char *identity_key);
extern int portillia_registry_offer_conn(const char *hostname, int sdk_fd);
extern char* portillia_registry_to_json();
extern bool portillia_registry_tunnel_status(const char *hostname, char *resolved_hostname, size_t resolved_hostname_len, bool *service_alive);
extern portillia_settings* portillia_server_get_settings();
extern const char* portillia_server_root_hostname();
extern int portillia_server_sni_port();
extern discovery_config *global_disc_cfg __attribute__((weak));

extern int portillia_network_ip_in_cidr(const char *ip, const char *cidr);

#define MAX_REGISTER_CHALLENGES 512
#define MAX_ACCESS_TOKENS 1024

typedef struct {
    bool in_use;
    char challenge_id[96];
    char siwe_message[2048];
    char identity_name[256];
    char identity_address[96];
    bool udp_enabled;
    bool tcp_enabled;
    time_t expires_at;
} register_challenge_entry;

typedef struct {
    bool in_use;
    char access_token[96];
    char hostname[256];
    char identity_name[256];
    char identity_address[96];
    bool udp_enabled;
    bool tcp_enabled;
    time_t expires_at;
} access_token_entry;

static register_challenge_entry g_register_challenges[MAX_REGISTER_CHALLENGES];
static access_token_entry g_access_tokens[MAX_ACCESS_TOKENS];

static char* trim_ascii(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

static void normalize_hostname(char *s) {
    if (!s) return;
    char *host = trim_ascii(s);
    if (host != s) memmove(s, host, strlen(host) + 1);
    char *slash = strchr(s, '/');
    if (slash) *slash = '\0';
    if (strchr(s, ':') && s[0] != '[') {
        char *colon = strrchr(s, ':');
        if (colon && strchr(colon + 1, ':') == NULL) *colon = '\0';
    }
    while (s[0] == '.') memmove(s, s + 1, strlen(s));
    size_t len = strlen(s);
    while (len > 0 && s[len - 1] == '.') s[--len] = '\0';
    for (size_t i = 0; i < len; i++) s[i] = (char)tolower((unsigned char)s[i]);
}

static void format_time_rfc3339(time_t t, char *out, size_t out_len) {
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

static void random_token(const char *prefix, char *out, size_t out_len) {
    unsigned int r = (unsigned int)rand();
    snprintf(out, out_len, "%s%u%ld", prefix, r, (long)time(NULL));
}

static register_challenge_entry* find_register_challenge(const char *challenge_id) {
    if (!challenge_id) return NULL;
    for (int i = 0; i < MAX_REGISTER_CHALLENGES; i++) {
        if (g_register_challenges[i].in_use &&
            strcmp(g_register_challenges[i].challenge_id, challenge_id) == 0) {
            return &g_register_challenges[i];
        }
    }
    return NULL;
}

static access_token_entry* find_access_token(const char *access_token) {
    if (!access_token) return NULL;
    for (int i = 0; i < MAX_ACCESS_TOKENS; i++) {
        if (g_access_tokens[i].in_use &&
            strcmp(g_access_tokens[i].access_token, access_token) == 0) {
            return &g_access_tokens[i];
        }
    }
    return NULL;
}

static const char* store_register_challenge(
    const char *identity_name,
    const char *identity_address,
    const char *siwe_message,
    bool udp_enabled,
    bool tcp_enabled,
    time_t expires_at
) {
    int slot = -1;
    for (int i = 0; i < MAX_REGISTER_CHALLENGES; i++) {
        if (!g_register_challenges[i].in_use) {
            slot = i;
            break;
        }
    }
    if (slot < 0) slot = (int)(rand() % MAX_REGISTER_CHALLENGES);
    register_challenge_entry *entry = &g_register_challenges[slot];
    memset(entry, 0, sizeof(*entry));
    entry->in_use = true;
    random_token("rch_", entry->challenge_id, sizeof(entry->challenge_id));
    snprintf(entry->siwe_message, sizeof(entry->siwe_message), "%s", siwe_message ? siwe_message : "");
    snprintf(entry->identity_name, sizeof(entry->identity_name), "%s", identity_name ? identity_name : "");
    snprintf(entry->identity_address, sizeof(entry->identity_address), "%s", identity_address ? identity_address : "");
    entry->udp_enabled = udp_enabled;
    entry->tcp_enabled = tcp_enabled;
    entry->expires_at = expires_at;
    return entry->challenge_id;
}

static const char* store_access_token(
    const char *hostname,
    const char *identity_name,
    const char *identity_address,
    bool udp_enabled,
    bool tcp_enabled,
    time_t expires_at
) {
    int slot = -1;
    for (int i = 0; i < MAX_ACCESS_TOKENS; i++) {
        if (!g_access_tokens[i].in_use) {
            slot = i;
            break;
        }
    }
    if (slot < 0) slot = (int)(rand() % MAX_ACCESS_TOKENS);
    access_token_entry *entry = &g_access_tokens[slot];
    memset(entry, 0, sizeof(*entry));
    entry->in_use = true;
    random_token("at_", entry->access_token, sizeof(entry->access_token));
    snprintf(entry->hostname, sizeof(entry->hostname), "%s", hostname ? hostname : "");
    snprintf(entry->identity_name, sizeof(entry->identity_name), "%s", identity_name ? identity_name : "");
    snprintf(entry->identity_address, sizeof(entry->identity_address), "%s", identity_address ? identity_address : "");
    entry->udp_enabled = udp_enabled;
    entry->tcp_enabled = tcp_enabled;
    entry->expires_at = expires_at;
    return entry->access_token;
}

static void derive_hostname(const char *identity_name, const char *identity_address, char *out, size_t out_len) {
    const char *root = portillia_server_root_hostname();
    if (!root || !root[0]) root = "localhost";
    const char *name = identity_name && identity_name[0] ? identity_name : identity_address;
    if (!name || !name[0]) name = "lease";
    if (strchr(name, '.')) {
        snprintf(out, out_len, "%s", name);
    } else {
        snprintf(out, out_len, "%s.%s", name, root);
    }
    normalize_hostname(out);
}

static int parse_hex_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int v = 0;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static bool verify_siwe_signature_address(const char *siwe_message, const char *siwe_signature, const char *expected_address) {
    if (!siwe_message || !siwe_signature || !expected_address) return false;
    const char *sig_hex = siwe_signature;
    if (sig_hex[0] == '0' && (sig_hex[1] == 'x' || sig_hex[1] == 'X')) sig_hex += 2;
    if (strlen(sig_hex) != 130) return false;

    uint8_t sig65[65];
    if (parse_hex_bytes(sig_hex, sig65, sizeof(sig65)) != 0) return false;

    // Extract recid from Ethereum v value.
    // Uncompressed: v = 27 + recid (range 27-30)
    // Compressed:   v = 31 + recid (range 31-34)
    int recid = (int)sig65[64];
    if (recid >= 27 && recid <= 30) {
        recid -= 27;
    } else if (recid >= 31 && recid <= 34) {
        recid -= 31;
    } else if (recid < 0 || recid > 3) {
        return false;
    }
    if (recid < 0 || recid > 3) return false;

    char prefix[64];
    snprintf(prefix, sizeof(prefix), "\x19Ethereum Signed Message:\n%zu", strlen(siwe_message));
    size_t payload_len = strlen(prefix) + strlen(siwe_message);
    uint8_t *payload = malloc(payload_len);
    if (!payload) return false;
    memcpy(payload, prefix, strlen(prefix));
    memcpy(payload + strlen(prefix), siwe_message, strlen(siwe_message));

    uint8_t hash[32];
    portillia_crypto_keccak256(payload, payload_len, hash);
    free(payload);

    // SIGN | VERIFY context is required for secp256k1_ecdsa_recover on some builds
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Explicitly separate r||s from v to avoid any boundary issue
    uint8_t rs64[64];
    memcpy(rs64, sig65, 64);

    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_pubkey pubkey;
    bool ok = false;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, rs64, recid) &&
        secp256k1_ecdsa_recover(ctx, &pubkey, &sig, hash)) {
        size_t pub_len = 65;
        uint8_t pub_buf[65];
        secp256k1_ec_pubkey_serialize(ctx, pub_buf, &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        char addr[43] = {0};
        portillia_crypto_pubkey_to_address(pub_buf, pub_len, addr);

        // Strip optional 0x prefix from expected_address before comparison
        const char *expected = expected_address;
        if (expected[0] == '0' && (expected[1] == 'x' || expected[1] == 'X')) expected += 2;
        ok = (strcasecmp(addr + 2, expected) == 0);
    }
    secp256k1_context_destroy(ctx);
    return ok;
}

/**
 * @brief Extract client IP, optionally trusting proxy headers.
 */
char* extract_client_ip(cwist_http_request *req) {
    portillia_settings *s = portillia_server_get_settings();
    char *remote_ip = cwist_http_header_get(req->headers, "X-Real-IP");
    if (s && s->trust_proxy_headers) {
        char *forwarded = cwist_http_header_get(req->headers, "X-Forwarded-For");
        if (forwarded) {
            // Take the first IP in the list
            char *comma = strchr(forwarded, ',');
            if (comma) *comma = '\0';
            return strdup(forwarded);
        }
    }
    // Fallback to real remote IP if available from socket (mocked here)
    return remote_ip ? strdup(remote_ip) : strdup("127.0.0.1");
}

/**
 * @brief Function handle_register
 */
void handle_register(cwist_http_request *req, cwist_http_response *res) {
    char *client_ip = extract_client_ip(req);
    LOG_INFO("Register request from %s", client_ip);
    free(client_ip);

    if (req->body && req->body->size > 0) {
        cJSON *root = cJSON_Parse(req->body->data);
        if (root) {
            cJSON *name = cJSON_GetObjectItem(root, "name");
            cJSON *identity = cJSON_GetObjectItem(root, "identity");
            cJSON *challenge_id = cJSON_GetObjectItem(root, "challenge_id");
            cJSON *siwe_message = cJSON_GetObjectItem(root, "siwe_message");
            cJSON *siwe_signature = cJSON_GetObjectItem(root, "siwe_signature");
            cJSON *bps_limit = cJSON_GetObjectItem(root, "bps_limit");
            
            cJSON *udp_enabled = cJSON_GetObjectItem(root, "udp_enabled");
            cJSON *tcp_enabled = cJSON_GetObjectItem(root, "tcp_enabled");
            
            char identity_name[256] = {0};
            char identity_address[96] = {0};
            bool udp = udp_enabled ? cJSON_IsTrue(udp_enabled) : false;
            bool tcp = tcp_enabled ? cJSON_IsTrue(tcp_enabled) : true;

            if (challenge_id && cJSON_IsString(challenge_id) && challenge_id->valuestring &&
                siwe_message && cJSON_IsString(siwe_message) && siwe_message->valuestring) {
                register_challenge_entry *challenge = find_register_challenge(challenge_id->valuestring);
                if (!challenge || !challenge->in_use || challenge->expires_at <= time(NULL)) {
                    res->status_code = CWIST_HTTP_NOT_FOUND;
                    cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"lease_not_found\", \"message\": \"register challenge not found\"}}");
                    cJSON_Delete(root);
                    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
                    return;
                }
                if (strcmp(challenge->siwe_message, siwe_message->valuestring) != 0) {
                    res->status_code = CWIST_HTTP_BAD_REQUEST;
                    cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"invalid_request\", \"message\": \"siwe message mismatch\"}}");
                    cJSON_Delete(root);
                    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
                    return;
                }
                if (!siwe_signature || !cJSON_IsString(siwe_signature) || !siwe_signature->valuestring ||
                    !verify_siwe_signature_address(siwe_message->valuestring, siwe_signature->valuestring, challenge->identity_address)) {
                    res->status_code = CWIST_HTTP_FORBIDDEN;
                    cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"unauthorized\", \"message\": \"siwe signature is invalid\"}}");
                    cJSON_Delete(root);
                    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
                    return;
                }
                snprintf(identity_name, sizeof(identity_name), "%s", challenge->identity_name);
                snprintf(identity_address, sizeof(identity_address), "%s", challenge->identity_address);
                udp = challenge->udp_enabled;
                tcp = challenge->tcp_enabled;
                challenge->in_use = false;
            } else if (identity && identity->valuestring) {
                if (name && name->valuestring) snprintf(identity_name, sizeof(identity_name), "%s", name->valuestring);
                snprintf(identity_address, sizeof(identity_address), "%s", identity->valuestring);
            } else if (identity && cJSON_IsObject(identity)) {
                cJSON *addr_obj = cJSON_GetObjectItem(identity, "address");
                cJSON *name_obj = cJSON_GetObjectItem(identity, "name");
                if (name_obj && cJSON_IsString(name_obj) && name_obj->valuestring) snprintf(identity_name, sizeof(identity_name), "%s", name_obj->valuestring);
                if (addr_obj && cJSON_IsString(addr_obj) && addr_obj->valuestring) snprintf(identity_address, sizeof(identity_address), "%s", addr_obj->valuestring);
            }

            if (identity_address[0]) {
                int64_t limit = bps_limit ? (int64_t)bps_limit->valuedouble : 0;
                char hostname[256] = {0};
                derive_hostname(identity_name, identity_address, hostname, sizeof(hostname));
                LOG_INFO("Registering lease for %s (bps_limit=%ld, udp=%d, tcp=%d)", hostname, limit, udp, tcp);
                portillia_registry_register(hostname, identity_address, limit);

                time_t expires_at = time(NULL) + 30;
                char expires_at_str[64] = {0};
                format_time_rfc3339(expires_at, expires_at_str, sizeof(expires_at_str));
                const char *access_token = store_access_token(
                    hostname,
                    identity_name,
                    identity_address,
                    udp,
                    tcp,
                    expires_at
                );

                cJSON *identity_obj = cJSON_CreateObject();
                cJSON_AddStringToObject(identity_obj, "name", identity_name);
                cJSON_AddStringToObject(identity_obj, "address", identity_address);

                cJSON *data = cJSON_CreateObject();
                cJSON_AddItemToObject(data, "identity", identity_obj);
                cJSON_AddStringToObject(data, "expires_at", expires_at_str);
                cJSON_AddStringToObject(data, "hostname", hostname);
                cJSON_AddStringToObject(data, "access_token", access_token);
                cJSON_AddBoolToObject(data, "udp_enabled", udp);
                cJSON_AddBoolToObject(data, "tcp_enabled", tcp);
                if (udp) {
                    cJSON_AddNumberToObject(data, "sni_port", (double)portillia_server_sni_port());
                }
                if (tcp) {
                    cJSON_AddStringToObject(data, "tcp_addr", "localhost:4017");
                }

                cJSON *res_root = cJSON_CreateObject();
                cJSON_AddBoolToObject(res_root, "ok", true);
                cJSON_AddItemToObject(res_root, "data", data);

                char *res_json = cJSON_PrintUnformatted(res_root);
                cwist_sstring_assign(res->body, res_json);
                free(res_json);
                cJSON_Delete(res_root);
            } else {
                res->status_code = CWIST_HTTP_BAD_REQUEST;
                cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"invalid_request\", \"message\": \"missing identity\"}}");
            }
            cJSON_Delete(root);
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_connect
 */
void handle_connect(cwist_http_request *req, cwist_http_response *res) {
    char hostname[256] = {0};
    char *token = cwist_http_header_get(req->headers, "X-Portal-Access-Token");
    if (token) {
        access_token_entry *entry = find_access_token(token);
        if (entry && entry->in_use && entry->expires_at > time(NULL)) {
            snprintf(hostname, sizeof(hostname), "%s", entry->hostname);
        }
    }
    if (!hostname[0]) {
        char *host = cwist_http_header_get(req->headers, "X-Portal-Hostname");
        if (!host) host = cwist_http_header_get(req->headers, "Host");
        if (host && host[0]) snprintf(hostname, sizeof(hostname), "%s", host);
        normalize_hostname(hostname);
    }
    if (!hostname[0]) {
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"invalid_request\", \"message\": \"missing hostname or access token\"}}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    send(req->client_fd, resp, strlen(resp), 0);
    req->upgraded = true;
    char *remote_addr = extract_client_ip(req);
    int ready = portillia_registry_offer_conn(hostname, req->client_fd);
    if (ready > 0) {
        LOG_INFO("sdk reverse connected address=%s lease_name=%s ready=%d remote_addr=%s", hostname, hostname, ready, remote_addr);
    } else {
        LOG_WARN("sdk reverse rejected address=%s lease_name=%s remote_addr=%s", hostname, hostname, remote_addr);
    }
    free(remote_addr);
}

/**
 * @brief Function handle_hop
 */
void handle_hop(cwist_http_request *req, cwist_http_response *res) {
    if (req->body && req->body->size > 0) {
        cJSON *root = cJSON_Parse(req->body->data);
        if (root) {
            cJSON *match_hostname = cJSON_GetObjectItem(root, "match_hostname");
            cJSON *match_token = cJSON_GetObjectItem(root, "match_token");
            cJSON *forward_token = cJSON_GetObjectItem(root, "forward_token");
            cJSON *forward_relay = cJSON_GetObjectItem(root, "forward_relay");
            cJSON *identity = cJSON_GetObjectItem(root, "identity");

            if (identity && forward_token && forward_relay) {
                cJSON *next_ipv4 = cJSON_GetObjectItem(forward_relay, "wireguard_ipv4");
                if (next_ipv4) {
                    if (match_hostname && match_hostname->valuestring) {
                        portillia_registry_register_hop(match_hostname->valuestring, next_ipv4->valuestring, forward_token->valuestring, identity->valuestring);
                    } else if (match_token && match_token->valuestring) {
                        portillia_registry_register_hop(match_token->valuestring, next_ipv4->valuestring, forward_token->valuestring, identity->valuestring);
                    }
                    cwist_sstring_assign(res->body, "{\"ok\": true}");
                }
            }
            cJSON_Delete(root);
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_discovery
 */
void handle_discovery(cwist_http_request *req, cwist_http_response *res) {
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "protocol_version", PORTILLIA_DISCOVERY_VERSION);
    char generated_at[64] = {0};
    format_time_rfc3339(time(NULL), generated_at, sizeof(generated_at));
    cJSON_AddStringToObject(data, "generated_at", generated_at);
    cJSON *relays = cJSON_CreateArray();
    if (global_disc_cfg && global_disc_cfg->relay_set) {
        portillia_relay_set *set = global_disc_cfg->relay_set;
        pthread_mutex_lock(&set->mu);
        for (int i = 0; i < set->count; i++) {
            portillia_relay_descriptor *d = &set->relays[i].descriptor;
            cJSON *item = cJSON_CreateObject();
            char issued_at[64] = {0};
            char expires_at[64] = {0};
            format_time_rfc3339(d->issued_at ? d->issued_at : time(NULL), issued_at, sizeof(issued_at));
            format_time_rfc3339(d->expires_at ? d->expires_at : (time(NULL) + 300), expires_at, sizeof(expires_at));
            cJSON_AddStringToObject(item, "address", d->address ? d->address : "");
            cJSON_AddStringToObject(item, "version", d->version ? d->version : PORTILLIA_RELEASE_VERSION);
            cJSON_AddStringToObject(item, "issued_at", issued_at);
            cJSON_AddStringToObject(item, "expires_at", expires_at);
            cJSON_AddStringToObject(item, "api_https_addr", d->api_https_addr ? d->api_https_addr : "");
            cJSON_AddStringToObject(item, "wireguard_public_key", d->wireguard_public_key ? d->wireguard_public_key : "");
            cJSON_AddNumberToObject(item, "wireguard_port", (double)d->wireguard_port);
            cJSON_AddBoolToObject(item, "supports_overlay", d->supports_overlay);
            cJSON_AddBoolToObject(item, "supports_udp", d->supports_udp);
            cJSON_AddBoolToObject(item, "supports_tcp", d->supports_tcp);
            cJSON_AddNumberToObject(item, "active_connections", (double)d->active_connections);
            cJSON_AddNumberToObject(item, "tcp_bps", d->tcp_bps);
            cJSON_AddStringToObject(item, "signature", d->signature ? d->signature : "");
            cJSON_AddItemToArray(relays, item);
        }
        pthread_mutex_unlock(&set->mu);
    }
    cJSON_AddItemToObject(data, "relays", relays);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "ok", true);
    cJSON_AddItemToObject(root, "data", data);
    char *json = cJSON_PrintUnformatted(root);
    cwist_sstring_assign(res->body, json);
    free(json);
    cJSON_Delete(root);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

void handle_tunnel_status(cwist_http_request *req, cwist_http_response *res) {
    const char *hostname_param = cwist_query_map_get(req->query_params, "hostname");
    char hostname[512];
    char resolved_hostname[512];
    bool service_alive = false;
    bool registered = false;

    snprintf(hostname, sizeof(hostname), "%s", hostname_param ? hostname_param : "");
    normalize_hostname(hostname);

    if (!hostname[0]) {
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"ok\":false,\"error\":{\"code\":\"invalid_request\",\"message\":\"hostname is required\"}}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    resolved_hostname[0] = '\0';
    registered = portillia_registry_tunnel_status(hostname, resolved_hostname, sizeof(resolved_hostname), &service_alive);

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "hostname", registered && resolved_hostname[0] ? resolved_hostname : hostname);
    cJSON_AddBoolToObject(data, "registered", registered);
    cJSON_AddBoolToObject(data, "service_alive", registered && service_alive);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "ok", true);
    cJSON_AddItemToObject(root, "data", data);
    char *json = cJSON_PrintUnformatted(root);
    cwist_sstring_assign(res->body, json);
    free(json);
    cJSON_Delete(root);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_admin_leases
 */
void handle_admin_leases(cwist_http_request *req, cwist_http_response *res) {
    char *json = portillia_registry_to_json();
    cwist_sstring_assign(res->body, json);
    free(json);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

extern int64_t portillia_proxy_get_active_conns();
extern double portillia_proxy_get_current_bps();

/**
 * @brief Function handle_admin_snapshot
 */
void handle_admin_snapshot(cwist_http_request *req, cwist_http_response *res) {
    portillia_settings *s = portillia_server_get_settings();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "approval_mode", s ? s->approval_mode : "auto");
    cJSON_AddBoolToObject(root, "landing_page_enabled", s ? s->landing_page_enabled : true);
    cJSON_AddNumberToObject(root, "active_connections", (double)portillia_proxy_get_active_conns());
    cJSON_AddNumberToObject(root, "tcp_bps", portillia_proxy_get_current_bps());
    
    char *leases_json = portillia_registry_to_json();
    cJSON *leases = cJSON_Parse(leases_json);
    cJSON_AddItemToObject(root, "leases", leases);
    free(leases_json);

    cJSON *udp = cJSON_CreateObject();
    cJSON_AddBoolToObject(udp, "enabled", s ? s->udp_enabled : true);
    cJSON_AddNumberToObject(udp, "max_leases", 0);
    cJSON_AddItemToObject(root, "udp", udp);

    cJSON *tcp = cJSON_CreateObject();
    cJSON_AddBoolToObject(tcp, "enabled", s ? s->tcp_port_enabled : true);
    cJSON_AddNumberToObject(tcp, "max_leases", 0);
    cJSON_AddItemToObject(root, "tcp_port", tcp);

    char *json = cJSON_PrintUnformatted(root);
    cwist_sstring_assign(res->body, json);
    free(json);
    cJSON_Delete(root);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_login
 */
void handle_login(cwist_http_request *req, cwist_http_response *res) {
    cwist_sstring_assign(res->body, "{\"ok\": true, \"token\": \"session-token\"}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
    cwist_http_header_add(&res->headers, "Set-Cookie", "portal_admin=session-token; Path=/admin; HttpOnly; Secure; SameSite=Strict");
}

/**
 * @brief Function handle_logout
 */
void handle_logout(cwist_http_request *req, cwist_http_response *res) {
    cwist_sstring_assign(res->body, "{\"ok\": true}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
    cwist_http_header_add(&res->headers, "Set-Cookie", "portal_admin=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=-1");
}

/**
 * @brief Function handle_domain
 */
void handle_domain(cwist_http_request *req, cwist_http_response *res) {
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "protocol_version", PORTILLIA_SDK_VERSION);
    cJSON_AddStringToObject(data, "release_version", PORTILLIA_RELEASE_VERSION);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "data", data);
    cJSON_AddBoolToObject(root, "ok", true);
    char *json = cJSON_PrintUnformatted(root);
    cwist_sstring_assign(res->body, json);
    free(json);
    cJSON_Delete(root);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_register_challenge
 */
void handle_register_challenge(cwist_http_request *req, cwist_http_response *res) {
    if (req->body && req->body->size > 0) {
        cJSON *req_root = cJSON_Parse(req->body->data);
        if (req_root) {
            cJSON *id_obj = cJSON_GetObjectItem(req_root, "identity");
            if (id_obj && cJSON_IsObject(id_obj)) {
                cJSON *addr_obj = cJSON_GetObjectItem(id_obj, "address");
                cJSON *name_obj = cJSON_GetObjectItem(id_obj, "name");
                cJSON *ttl_obj = cJSON_GetObjectItem(req_root, "ttl");
                cJSON *udp_obj = cJSON_GetObjectItem(req_root, "udp_enabled");
                cJSON *tcp_obj = cJSON_GetObjectItem(req_root, "tcp_enabled");
                const char *addr = (addr_obj && cJSON_IsString(addr_obj)) ? addr_obj->valuestring : "";
                const char *name = (name_obj && cJSON_IsString(name_obj)) ? name_obj->valuestring : "";
                int ttl = (ttl_obj && cJSON_IsNumber(ttl_obj)) ? ttl_obj->valueint : 30;
                if (ttl <= 0) ttl = 30;
                bool udp = udp_obj ? cJSON_IsTrue(udp_obj) : false;
                bool tcp = tcp_obj ? cJSON_IsTrue(tcp_obj) : true;
                char domain[256] = {0};
                char *host_header = cwist_http_header_get(req->headers, "Host");
                if (host_header && host_header[0]) {
                    snprintf(domain, sizeof(domain), "%s", host_header);
                    normalize_hostname(domain);
                }
                if (!domain[0]) {
                    const char *root_host = portillia_server_root_hostname();
                    snprintf(domain, sizeof(domain), "%s", root_host && root_host[0] ? root_host : "localhost");
                }
                char issued_at[64] = {0};
                char expires_at[64] = {0};
                time_t now = time(NULL);
                time_t exp = now + ttl;
                format_time_rfc3339(now, issued_at, sizeof(issued_at));
                format_time_rfc3339(exp, expires_at, sizeof(expires_at));
                char msg[2048];
                snprintf(
                    msg,
                    sizeof(msg),
                    "%s wants you to sign in with your Ethereum account:\n%s\n\nRegister a portal lease\n\nURI: https://%s/sdk/register\nVersion: 1\nChain ID: 1\nNonce: %u\nIssued At: %s\nExpiration Time: %s",
                    domain,
                    addr,
                    domain,
                    (unsigned int)rand(),
                    issued_at,
                    expires_at
                );
                const char *challenge_id = store_register_challenge(name, addr, msg, udp, tcp, exp);
                cJSON *root = cJSON_CreateObject();
                cJSON *data = cJSON_CreateObject();
                cJSON_AddStringToObject(data, "challenge_id", challenge_id);
                cJSON_AddStringToObject(data, "expires_at", expires_at);
                cJSON_AddStringToObject(data, "siwe_message", msg);
                cJSON_AddItemToObject(root, "data", data);
                cJSON_AddBoolToObject(root, "ok", true);
                
                char *json = cJSON_PrintUnformatted(root);
                cwist_sstring_assign(res->body, json);
                free(json);
                cJSON_Delete(root);
            }
            cJSON_Delete(req_root);
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_renew
 */
void handle_renew(cwist_http_request *req, cwist_http_response *res) {
    if (!req->body || req->body->size == 0) {
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"invalid_request\", \"message\": \"missing renew payload\"}}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }
    cJSON *root = cJSON_Parse(req->body->data);
    if (!root) {
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"invalid_request\", \"message\": \"invalid json\"}}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }
    cJSON *token_obj = cJSON_GetObjectItem(root, "access_token");
    cJSON *ttl_obj = cJSON_GetObjectItem(root, "ttl");
    if (!token_obj || !cJSON_IsString(token_obj) || !token_obj->valuestring) {
        cJSON_Delete(root);
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"invalid_request\", \"message\": \"access token is required\"}}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }
    access_token_entry *entry = find_access_token(token_obj->valuestring);
    if (!entry || !entry->in_use) {
        cJSON_Delete(root);
        res->status_code = CWIST_HTTP_NOT_FOUND;
        cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": {\"code\": \"lease_not_found\", \"message\": \"lease not found\"}}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }
    int ttl = (ttl_obj && cJSON_IsNumber(ttl_obj)) ? ttl_obj->valueint : 30;
    if (ttl <= 0) ttl = 30;
    entry->expires_at = time(NULL) + ttl;
    portillia_registry_register(entry->hostname, entry->identity_address, 0);
    char expires_at_str[64] = {0};
    format_time_rfc3339(entry->expires_at, expires_at_str, sizeof(expires_at_str));
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "expires_at", expires_at_str);
    cJSON_AddStringToObject(data, "access_token", entry->access_token);
    cJSON *resp_root = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp_root, "ok", true);
    cJSON_AddItemToObject(resp_root, "data", data);
    char *json = cJSON_PrintUnformatted(resp_root);
    cwist_sstring_assign(res->body, json);
    free(json);
    cJSON_Delete(resp_root);
    cJSON_Delete(root);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_unregister
 */
void handle_unregister(cwist_http_request *req, cwist_http_response *res) {
    if (req->body && req->body->size > 0) {
        cJSON *root = cJSON_Parse(req->body->data);
        if (root) {
            cJSON *token_obj = cJSON_GetObjectItem(root, "access_token");
            if (token_obj && cJSON_IsString(token_obj) && token_obj->valuestring) {
                access_token_entry *entry = find_access_token(token_obj->valuestring);
                if (entry) entry->in_use = false;
            }
            cJSON_Delete(root);
        }
    }
    cwist_sstring_assign(res->body, "{\"ok\": true, \"data\": {}}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_healthz
 */
void handle_healthz(cwist_http_request *req, cwist_http_response *res) {
    (void)req;
    cwist_sstring_assign(res->body, "{\"ok\":true,\"status\":\"ok\",\"data\":{\"status\":\"ok\"}}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

#include <portillia/portal/settings.h>

extern portillia_settings* portillia_server_get_settings();
extern char* extract_client_ip(cwist_http_request *req);
extern void portillia_settings_save(const char *path, portillia_settings *s);

static char *settings_path = NULL;

/**
 * @brief Function handle_admin_action
 * Routes granular lease management actions (ban, bps, approve).
 */
void handle_admin_action(cwist_http_request *req, cwist_http_response *res) {
    char *path_copy = strdup(req->path->data);
    portillia_settings *s = portillia_server_get_settings();
    if (!s) { res->status_code = CWIST_HTTP_INTERNAL_ERROR; free(path_copy); return; }

    char name_buf[256] = {0}, addr_buf[256] = {0}, action_buf[64] = {0};
    if (sscanf(path_copy + strlen("/admin/leases/"), "%[^/]/%[^/]/%s", name_buf, addr_buf, action_buf) == 3) {
        // Go's admin panel sends identity.Name and identity.Address base64url encoded.
        // Simplified: use raw for now if not encoded.
        // char decoded_name[256], decoded_addr[256];
        // base64url_decode(name_buf, strlen(name_buf), decoded_name);
        // base64url_decode(addr_buf, strlen(addr_buf), decoded_addr);

        char identity_key[512];
        snprintf(identity_key, sizeof(identity_key), "%s", addr_buf); // Assuming address is the key

        // Use the actual path from the settings object
        char *settings_file_path = s->path;
        LOG_INFO("Admin: Action %s on identity %s", action_buf, identity_key);

        if (strcmp(action_buf, "ban") == 0) {
            portillia_settings_ban_identity(s, identity_key);
            portillia_settings_save(settings_file_path, s);
            cwist_sstring_assign(res->body, "{\"ok\": true}");
        } else if (strcmp(action_buf, "unban") == 0) {
            portillia_settings_unban_identity(s, identity_key);
            portillia_settings_save(settings_file_path, s);
            cwist_sstring_assign(res->body, "{\"ok\": true}");
        } else if (strcmp(action_buf, "approve") == 0) {
            portillia_settings_approve_identity(s, identity_key);
            portillia_settings_save(settings_file_path, s);
            cwist_sstring_assign(res->body, "{\"ok\": true}");
        } else if (strcmp(action_buf, "bps") == 0) {
            if (req->body && req->body->size > 0) {
                cJSON *root = cJSON_Parse(req->body->data);
                if (root) {
                    cJSON *bps_obj = cJSON_GetObjectItem(root, "bps");
                    if (bps_obj) {
                        int64_t bps = (int64_t)bps_obj->valuedouble;
                        LOG_INFO("Admin: Setting BPS to %ld for %s", bps, identity_key);
                        // Update lease registry with BPS (re-registering for simplicity)
                        extern void portillia_registry_update_bps(const char *identity_key, int64_t bps);
                        portillia_registry_update_bps(identity_key, bps);
                        cwist_sstring_assign(res->body, "{\"ok\": true}");
                    }
                    cJSON_Delete(root);
                }
            }
        } else {
            res->status_code = CWIST_HTTP_NOT_FOUND;
        }
    } else {
        res->status_code = CWIST_HTTP_BAD_REQUEST;
    }
    free(path_copy);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_admin_landing_page
 */
void handle_admin_landing_page(cwist_http_request *req, cwist_http_response *res) {
    portillia_settings *s = portillia_server_get_settings();
    if (!s) { res->status_code = CWIST_HTTP_INTERNAL_ERROR; return; }

    if (req->body && req->body->size > 0) {
        cJSON *root = cJSON_Parse(req->body->data);
        if (root) {
            cJSON *enabled = cJSON_GetObjectItem(root, "enabled");
            if (enabled) {
                s->landing_page_enabled = cJSON_IsTrue(enabled);
                portillia_settings_save(s->path, s); // Assuming path is stored in settings
                cwist_sstring_assign(res->body, "{\"ok\": true}");
            }
            cJSON_Delete(root);
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_admin_udp_settings
 */
void handle_admin_udp_settings(cwist_http_request *req, cwist_http_response *res) {
    portillia_settings *s = portillia_server_get_settings();
    if (!s) { res->status_code = CWIST_HTTP_INTERNAL_ERROR; return; }

    if (req->method == CWIST_HTTP_GET) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "enabled", s->udp_enabled);
        cJSON_AddNumberToObject(root, "max_leases", 0);
        char *json = cJSON_PrintUnformatted(root);
        cwist_sstring_assign(res->body, json);
        free(json);
        cJSON_Delete(root);
    } else if (req->method == CWIST_HTTP_POST) {
        if (req->body && req->body->size > 0) {
            cJSON *root = cJSON_Parse(req->body->data);
            if (root) {
                cJSON *enabled = cJSON_GetObjectItem(root, "enabled");
                if (enabled) {
                    s->udp_enabled = cJSON_IsTrue(enabled);
                    portillia_settings_save(s->path, s);
                    cwist_sstring_assign(res->body, "{\"ok\": true}");
                }
                cJSON_Delete(root);
            }
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_admin_tcp_port_settings
 */
void handle_admin_tcp_port_settings(cwist_http_request *req, cwist_http_response *res) {
    portillia_settings *s = portillia_server_get_settings();
    if (!s) { res->status_code = CWIST_HTTP_INTERNAL_ERROR; return; }

    if (req->method == CWIST_HTTP_GET) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "enabled", s->tcp_port_enabled);
        cJSON_AddNumberToObject(root, "max_leases", 0);
        char *json = cJSON_PrintUnformatted(root);
        cwist_sstring_assign(res->body, json);
        free(json);
        cJSON_Delete(root);
    } else if (req->method == CWIST_HTTP_POST) {
        if (req->body && req->body->size > 0) {
            cJSON *root = cJSON_Parse(req->body->data);
            if (root) {
                cJSON *enabled = cJSON_GetObjectItem(root, "enabled");
                if (enabled) {
                    s->tcp_port_enabled = cJSON_IsTrue(enabled);
                    portillia_settings_save(s->path, s);
                    cwist_sstring_assign(res->body, "{\"ok\": true}");
                }
                cJSON_Delete(root);
            }
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_admin_approval_mode
 */
void handle_admin_approval_mode(cwist_http_request *req, cwist_http_response *res) {
    portillia_settings *s = portillia_server_get_settings();
    if (!s) { res->status_code = CWIST_HTTP_INTERNAL_ERROR; return; }

    if (req->method == CWIST_HTTP_GET) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "approval_mode", s->approval_mode);
        char *json = cJSON_PrintUnformatted(root);
        cwist_sstring_assign(res->body, json);
        free(json);
        cJSON_Delete(root);
    } else if (req->method == CWIST_HTTP_POST) {
        if (req->body && req->body->size > 0) {
            cJSON *root = cJSON_Parse(req->body->data);
            if (root) {
                cJSON *mode = cJSON_GetObjectItem(root, "mode");
                if (mode && mode->valuestring) {
                    free(s->approval_mode);
                    s->approval_mode = strdup(mode->valuestring);
                    portillia_settings_save(s->path, s);
                    cwist_sstring_assign(res->body, "{\"ok\": true}");
                }
                cJSON_Delete(root);
            }
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function portillia_api_server_setup
 */
void portillia_api_server_setup(cwist_app *app) {
    cwist_app_get(app, "/healthz", handle_healthz);
    cwist_app_get(app, "/tunnel/status", handle_tunnel_status);
    cwist_app_get(app, "/sdk/domain", handle_domain);
    cwist_app_post(app, "/sdk/register/challenge", handle_register_challenge);
    cwist_app_post(app, "/sdk/register", handle_register);
    cwist_app_get(app, "/sdk/connect", handle_connect);
    cwist_app_post(app, "/sdk/renew", handle_renew);
    cwist_app_post(app, "/sdk/unregister", handle_unregister);
    cwist_app_post(app, "/sdk/hop", handle_hop);
    cwist_app_get(app, "/discovery", handle_discovery);
    
    // Admin APIs
    cwist_app_get(app, "/admin/snapshot", handle_admin_snapshot);
    cwist_app_post(app, "/admin/login", handle_login);
    cwist_app_post(app, "/admin/logout", handle_logout);
    cwist_app_get(app, "/admin/leases", handle_admin_leases);
    cwist_app_post(app, "/admin/leases/*", handle_admin_action);
    cwist_app_delete(app, "/admin/leases/*", handle_admin_action);

    cwist_app_get(app, "/admin/settings/landing-page", handle_admin_landing_page);
    cwist_app_post(app, "/admin/settings/landing-page", handle_admin_landing_page);
    cwist_app_get(app, "/admin/settings/udp", handle_admin_udp_settings);
    cwist_app_post(app, "/admin/settings/udp", handle_admin_udp_settings);
    cwist_app_get(app, "/admin/settings/tcp-port", handle_admin_tcp_port_settings);
    cwist_app_post(app, "/admin/settings/tcp-port", handle_admin_tcp_port_settings);
    cwist_app_get(app, "/admin/settings/approval-mode", handle_admin_approval_mode);
    cwist_app_post(app, "/admin/settings/approval-mode", handle_admin_approval_mode);

    cwist_app_post(app, "/api/v2/register", handle_register);
    cwist_app_get(app, "/api/v2/discovery", handle_discovery);
}
