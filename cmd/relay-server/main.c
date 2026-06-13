#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>
#include <portillia/portal/acme/manager.h>
#include <portillia/portal/discovery/discovery.h>
#include <portillia/portal/identity.h>
#include <portillia/portal/settings.h>
#include <portillia/portal/api_server_relay.h>
#include <portillia/portal/keyless/ech.h>
#include <portillia/portal/keyless/server.h>
#include <portillia/portal/api_server.h>
#include <cwist/security/tls/ech.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <wireguard_proto.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>
#include "portal_bridge.h"

extern char *get_sni_hostname(int client_fd);
discovery_config *global_disc_cfg = NULL;
portillia_acme_manager *global_acme_manager = NULL;
portillia_relay_identity *global_relay_identity = NULL;

typedef struct {
    int sni_port;
    int api_port;
} listener_args;

#include <errno.h>
#include <string.h>

static void *sni_worker_thread(void *arg) {
    int client = (int)(intptr_t)arg;
    char *sni = get_sni_hostname(client);
    if (sni) {
        extern void portillia_server_handle_connect(const char *hostname, int client_fd);
        portillia_server_handle_connect(sni, client);
        free(sni);
    } else {
        LOG_DEBUG("sni_listener: no SNI, closing client");
        close(client);
    }
    return NULL;
}

void *sni_listener_thread(void *arg) {
    listener_args *args = (listener_args *)arg;
    int port = args->sni_port;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Unified listener: Failed to bind to port %d: %s", port, strerror(errno));
        return NULL;
    }
    listen(fd, 128);
    while (1) {
        int client = accept(fd, NULL, NULL);
        if (client < 0) continue;

        pthread_t tid;
        if (pthread_create(&tid, NULL, sni_worker_thread, (void *)(intptr_t)client) != 0) {
            LOG_WARN("sni_listener: failed to spawn worker, closing client");
            close(client);
            continue;
        }
        pthread_detach(tid);
    }
    return NULL;
}

typedef struct wg_peer {
    char pubkey[128];
    char endpoint[128];
    struct wg_peer *next;
} wg_peer_t;

static wg_peer_t *peer_list = NULL;
static pthread_mutex_t peer_list_lock = PTHREAD_MUTEX_INITIALIZER;

void add_wg_peer(const char *pubkey, const char *endpoint) {
    pthread_mutex_lock(&peer_list_lock);
    wg_peer_t *p = malloc(sizeof(wg_peer_t));
    strncpy(p->pubkey, pubkey, 127);
    strncpy(p->endpoint, endpoint, 127);
    p->next = peer_list;
    peer_list = p;
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "wg set wg0 peer %s endpoint %s allowed-ips 10.0.0.0/24", pubkey, endpoint);
    system(cmd);
    pthread_mutex_unlock(&peer_list_lock);
}

void *wg_listener_thread(void *arg) {
    (void)arg;
    
    // In production, we'd listen for discovery updates and call add_wg_peer
    while (1) {
        // Mock event loop for peer discovery
        sleep(60); 
    }
    return NULL;
}

void *hop_accept_thread(void *arg) {
    (void)arg;
    LOG_INFO("hop accept thread started");
    while (1) {
        char *token = NULL;
        int fd = HopMuxAcceptFD(&token);
        if (fd >= 0 && token) {
            extern void portillia_server_handle_hop_stream(int fd, const char *token);
            portillia_server_handle_hop_stream(fd, token);
            FreeCString(token);
        } else {
            if (token) FreeCString(token);
            if (fd >= 0) close(fd);
            usleep(100000); // 100ms retry
        }
    }
    return NULL;
}

static char *replace_str(const char *str, const char *old_str, const char *new_str) {
    char *result;
    int i, count = 0;
    int newlen = strlen(new_str);
    int oldlen = strlen(old_str);
    for (i = 0; str[i] != '\0'; i++) {
        if (strstr(&str[i], old_str) == &str[i]) {
            count++;
            i += oldlen - 1;
        }
    }
    result = (char *)malloc(i + count * (newlen - oldlen) + 1);
    i = 0;
    while (*str) {
        if (strstr(str, old_str) == str) {
            strcpy(&result[i], new_str);
            i += newlen;
            str += oldlen;
        } else
            result[i++] = *str++;
    }
    result[i] = '\0';
    return result;
}

extern portillia_settings* portillia_server_get_settings();

void fallback_spa_handler_clean(cwist_http_request *req, cwist_http_response *res) {
    portillia_settings *settings = portillia_server_get_settings();
    if (settings && !settings->landing_page_enabled) {
        res->status_code = CWIST_HTTP_NOT_FOUND;
        cwist_sstring_assign(res->body, "Landing page disabled");
        return;
    }

    LOG_INFO("Serving SPA fallback for %s", req->path->data);
    const char *static_dir = getenv("STATIC_DIR") ? getenv("STATIC_DIR") : "cmd/relay-server/dist/app";
    char path[1024];
    snprintf(path, sizeof(path), "%s/portal.html", static_dir);
    FILE *f = fopen(path, "rb");
    if (!f) {
        res->status_code = CWIST_HTTP_NOT_FOUND;
        cwist_sstring_assign(res->body, "Not Found");
        return;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *html = malloc(fsize + 1);
    if (!html) { fclose(f); return; }
    fread(html, 1, fsize, f);
    fclose(f);
    html[fsize] = 0;
    
    char *final_html = malloc(fsize + 8192);
    if (!final_html) { free(html); return; }
    final_html[0] = '\0';
    
    char *head_end = strstr(html, "</head>");
    if (head_end) {
        size_t head_len = head_end - html;
        memcpy(final_html, html, head_len);
        final_html[head_len] = '\0';
        strcat(final_html, "<script id=\"__SSR_DATA__\" type=\"application/json\">[]</script>\n</head>");
        strcat(final_html, head_end + 7);
    } else {
        strcpy(final_html, html);
    }
    free(html);
    
    char *r1 = replace_str(final_html, "[%OG_TITLE%]", "Portal Proxy Gateway");
    char *r2 = replace_str(r1, "[%OG_DESCRIPTION%]", "Transform your local services into web-accessible endpoints. Instant access from anywhere.");
    char *r3 = replace_str(r2, "[%LANDING_PAGE_ENABLED%]", "true");
    char *r4 = replace_str(r3, "[%RELEASE_VERSION%]", PORTILLIA_RELEASE_VERSION);
    
    cwist_sstring_assign(res->body, r4);
    free(final_html); free(r1); free(r2); free(r3); free(r4);
    
    cwist_http_header_add(&res->headers, "Content-Type", "text/html; charset=utf-8");
    cwist_http_header_add(&res->headers, "Cache-Control", "no-cache, must-revalidate");
}

void spa_error_handler(cwist_http_request *req, cwist_http_response *res, cwist_http_status_t status) {
    if (status == CWIST_HTTP_NOT_FOUND && req->method == CWIST_HTTP_GET) {
        const char *static_dir = getenv("STATIC_DIR") ? getenv("STATIC_DIR") : "cmd/relay-server/dist/app";
        char fs_path[1024];
        snprintf(fs_path, sizeof(fs_path), "%s%s", static_dir, req->path->data);
        
        struct stat st;
        if (stat(fs_path, &st) == 0 && S_ISREG(st.st_mode)) {
            cwist_http_response_send_file(res, fs_path, NULL, NULL);
            res->status_code = CWIST_HTTP_OK;
            return;
        }

        const char *dot = strrchr(req->path->data, '.');
        if (dot && strchr(dot, '/') == NULL) {
            res->status_code = CWIST_HTTP_NOT_FOUND;
            cwist_sstring_assign(res->body, "404 Not Found");
            return;
        }
        
        fallback_spa_handler_clean(req, res);
        res->status_code = CWIST_HTTP_OK;
    }
}

void *acme_renewal_thread(void *arg) {
    (void)arg;
    LOG_INFO("ACME renewal thread started.");
    while (1) {
        sleep(24 * 60 * 60); // Check every 24 hours (Go's defaultRenewInterval)
        if (global_acme_manager) {
            char *cert_file = NULL, *key_file = NULL;
            LOG_INFO("Attempting ACME certificate renewal.");
            if (portillia_acme_manager_ensure_certificate(global_acme_manager, &cert_file, &key_file) == CWIST_SUCCESS) {
                LOG_INFO("ACME certificate renewed successfully.");
                // In a full implementation, we'd notify the API server to reload TLS configs
                free(cert_file); free(key_file);
            } else {
                LOG_ERROR("ACME certificate renewal failed.");
            }
            portillia_acme_manager_sync_dns(global_acme_manager);
            if (global_acme_manager->cfg.ens_gasless_enabled) portillia_acme_manager_sync_ens_gasless(global_acme_manager);
        }
    }
    return NULL;
}

static const char *env_str_or_default(const char *name, const char *default_value) {
    const char *value = getenv(name);
    if (!value || strlen(value) == 0) {
        return default_value;
    }
    return value;
}

static int env_int_or_default(const char *name, int default_value) {
    const char *value = getenv(name);
    if (!value || strlen(value) == 0) {
        return default_value;
    }
    return atoi(value);
}

static bool env_bool_or_default(const char *name, bool default_value) {
    const char *value = getenv(name);
    if (!value || strlen(value) == 0) {
        return default_value;
    }
    char buf[16];
    size_t i = 0;
    for (; value[i] != '\0' && i < sizeof(buf) - 1; i++) {
        buf[i] = (char)tolower((unsigned char)value[i]);
    }
    buf[i] = '\0';
    if (strcmp(buf, "1") == 0 || strcmp(buf, "true") == 0 || strcmp(buf, "yes") == 0 || strcmp(buf, "on") == 0) {
        return true;
    }
    if (strcmp(buf, "0") == 0 || strcmp(buf, "false") == 0 || strcmp(buf, "no") == 0 || strcmp(buf, "off") == 0) {
        return false;
    }
    return default_value;
}

static const char *bool_str(bool value) {
    return value ? "true" : "false";
}

#define PORTAL_RELAY_REGISTRY_URL "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json"

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

static char *fetch_remote_registry(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct curl_response res = { .data = malloc(1), .size = 0 };
    res.data[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_URL, PORTAL_RELAY_REGISTRY_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    portillia_network_configure_curl_tls(curl, false);
    CURLcode code = curl_easy_perform(curl);
    char *result = NULL;
    if (code == CURLE_OK) {
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (status == 200) {
            cJSON *root = cJSON_Parse(res.data);
            if (root) {
                cJSON *relays = cJSON_GetObjectItem(root, "relays");
                if (cJSON_IsArray(relays)) {
                    int count = cJSON_GetArraySize(relays);
                    size_t total = 0;
                    for (int i = 0; i < count; i++) {
                        cJSON *item = cJSON_GetArrayItem(relays, i);
                        if (cJSON_IsString(item) && item->valuestring) total += strlen(item->valuestring) + 1;
                    }
                    if (total > 0) {
                        result = malloc(total);
                        if (result) {
                            result[0] = '\0';
                            size_t off = 0;
                            for (int i = 0; i < count; i++) {
                                cJSON *item = cJSON_GetArrayItem(relays, i);
                                if (cJSON_IsString(item) && item->valuestring) {
                                    if (off > 0) result[off++] = ',';
                                    size_t len = strlen(item->valuestring);
                                    memcpy(result + off, item->valuestring, len);
                                    off += len;
                                    result[off] = '\0';
                                }
                            }
                        }
                    }
                }
                cJSON_Delete(root);
            }
        } else {
            LOG_WARN("remote registry fetch failed status=%ld", status);
        }
    } else {
        LOG_WARN("remote registry fetch failed error=%s", curl_easy_strerror(code));
    }
    free(res.data);
    curl_easy_cleanup(curl);
    return result;
}

static char *resolve_portal_relay_urls(const char *bootstraps, bool include_defaults, const char *portal_url) {
    size_t total = 0;
    if (bootstraps && strlen(bootstraps) > 0) total += strlen(bootstraps);

    char *remote = include_defaults ? fetch_remote_registry() : NULL;
    if (remote && strlen(remote) > 0) {
        if (total > 0) total++;
        total += strlen(remote);
    }

    if (total == 0) {
        free(remote);
        return NULL;
    }

    char *result = malloc(total + 1);
    if (!result) { free(remote); return NULL; }
    result[0] = '\0';

    size_t off = 0;
    if (bootstraps && strlen(bootstraps) > 0) {
        strcpy(result + off, bootstraps);
        off += strlen(bootstraps);
    }
    if (remote && strlen(remote) > 0) {
        if (off > 0) result[off++] = ',';
        strcpy(result + off, remote);
        off += strlen(remote);
    }
    result[off] = '\0';
    free(remote);

    /* Remove self URL from bootstraps (Go: RemoveRelayURL) */
    if (portal_url && portal_url[0]) {
        char *copy = strdup(result);
        char *out = malloc(strlen(result) + 1);
        if (out && copy) {
            out[0] = '\0';
            size_t out_off = 0;
            char *saveptr = NULL;
            char *token = strtok_r(copy, ",", &saveptr);
            bool first = true;
            while (token) {
                while (*token == ' ') token++;
                if (strcmp(token, portal_url) != 0 && strcasecmp(token, portal_url) != 0) {
                    if (!first) { out[out_off++] = ','; out[out_off] = '\0'; }
                    strcpy(out + out_off, token);
                    out_off += strlen(token);
                    first = false;
                }
                token = strtok_r(NULL, ",", &saveptr);
            }
            free(copy);
            free(result);
            result = out;
        } else {
            free(copy);
            free(out);
        }
    }

    return result;
}

static char *portal_root_hostname(const char *portal_url) {
    if (!portal_url) {
        return strdup("localhost");
    }
    const char *start = strstr(portal_url, "://");
    start = start ? start + 3 : portal_url;
    const char *end = strpbrk(start, ":/");
    size_t length = end ? (size_t)(end - start) : strlen(start);
    if (length == 0) {
        return strdup("localhost");
    }
    while (length > 0 && start[length - 1] == '.') {
        length--;
    }
    if (length == 0) {
        return strdup("localhost");
    }
    char *host = calloc(length + 1, 1);
    for (size_t i = 0; i < length; i++) {
        host[i] = (char)tolower((unsigned char)start[i]);
    }
    host[length] = '\0';
    return host;
}

static char *portal_public_url(const char *portal_url) {
    char *host = portal_root_hostname(portal_url);
    if (!host || !host[0]) {
        if (host) free(host);
        return strdup("https://localhost");
    }
    size_t len = strlen(host);
    char *url = calloc(len + 9, 1);
    if (!url) {
        free(host);
        return NULL;
    }
    snprintf(url, len + 9, "https://%s", host);
    free(host);
    return url;
}

int main(void) {
    portillia_manifest_init();
    const char *portal_url = env_str_or_default("PORTAL_URL", "https://localhost:4017");
    const char *advertise_url_env = env_str_or_default("ADVERTISE_URL", "");
    const char *identity_path = env_str_or_default("IDENTITY_PATH", "./.portal-certs");
    const char *bootstraps = env_str_or_default("BOOTSTRAPS", "");
    const bool discovery_enabled = env_bool_or_default("DISCOVERY", false);
    int api_port = env_int_or_default("API_PORT", 4017);
    int sni_port = env_int_or_default("SNI_PORT", 443);
    int wg_port = env_int_or_default("WIREGUARD_PORT", 51820);
    int min_port = env_int_or_default("MIN_PORT", 0);
    int max_port = env_int_or_default("MAX_PORT", 0);
    int max_routing = env_int_or_default("MAX_ROUTING", 1);
    const bool udp_enabled = env_bool_or_default("UDP_ENABLED", false);
    const bool tcp_enabled = env_bool_or_default("TCP_ENABLED", false);
    const bool landing_page_enabled = env_bool_or_default("LANDING_PAGE_ENABLED", false);
    const bool trust_proxy_headers = env_bool_or_default("TRUST_PROXY_HEADERS", false);
    const bool pprof_enabled = env_bool_or_default("PPROF_ENABLED", false);
    const char *pprof_addr = env_str_or_default("PPROF_ADDR", "127.0.0.1:6060");
    const char *trusted_proxy_cidrs = env_str_or_default("TRUSTED_PROXY_CIDRS", "");
    const char *headless_shell_url = env_str_or_default("HEADLESS_SHELL_URL", "");
    const char *acme_dns_provider = env_str_or_default("ACME_DNS_PROVIDER", "");
    const bool ens_gasless_enabled = env_bool_or_default("ENS_GASLESS_ENABLED", false);
    char *root_hostname = portal_root_hostname(portal_url);
    char *public_relay_url = (advertise_url_env && advertise_url_env[0])
        ? strdup(advertise_url_env)
        : portal_public_url(portal_url);

    portillia_acme_config acme_cfg = {
        .base_domain = root_hostname,
        .key_dir = (char *)identity_path,
        .dns_provider_type = (char *)acme_dns_provider,
        .ens_gasless_enabled = ens_gasless_enabled,
        .ens_gasless_address = getenv("ENS_GASLESS_ADDRESS"),
        .cloudflare_token = getenv("CLOUDFLARE_TOKEN"),
        .gcp_project_id = getenv("GCP_PROJECT_ID"),
        .gcp_managed_zone = getenv("GCP_MANAGED_ZONE"),
        .njalla_token = getenv("NJALLA_TOKEN"),
        .aws_access_key_id = getenv("AWS_ACCESS_KEY_ID"),
        .aws_secret_access_key = getenv("AWS_SECRET_ACCESS_KEY"),
        .aws_session_token = getenv("AWS_SESSION_TOKEN"),
        .aws_region = getenv("AWS_REGION"),
        .aws_hosted_zone_id = getenv("AWS_HOSTED_ZONE_ID"),
        .aws_kms_key_arn = getenv("AWS_DNSSEC_KMS_KEY_ARN")
    };

    bool ech_enabled = false;
    LOG_INFO(
        "configured relay server acme_dns_provider=%s api_port=%d bootstraps=%s discovery_enabled=%s ech_enabled=%s ens_gasless_enabled=%s headless_shell_enabled=%s identity_path=%s landing_page_enabled=%s max_port=%d min_port=%d portal_url=%s pprof_addr=%s pprof_enabled=%s release_version=%s sni_port=%d tcp_enabled=%s trust_proxy_headers=%s trusted_proxy_cidrs=%s udp_enabled=%s wireguard_port=%d",
        acme_dns_provider,
        api_port,
        bootstraps,
        bool_str(discovery_enabled),
        bool_str(ech_enabled),
        bool_str(ens_gasless_enabled),
        bool_str(strlen(headless_shell_url) > 0),
        identity_path,
        bool_str(landing_page_enabled),
        max_port,
        min_port,
        portal_url,
        pprof_addr,
        bool_str(pprof_enabled),
        PORTILLIA_RELEASE_VERSION,
        sni_port,
        bool_str(tcp_enabled),
        bool_str(trust_proxy_headers),
        trusted_proxy_cidrs,
        bool_str(udp_enabled),
        wg_port
    );

    char settings_path[1024];
    snprintf(settings_path, sizeof(settings_path), "%s/settings.json", identity_path);
    portillia_settings *settings = portillia_settings_load(settings_path);
    settings->landing_page_enabled = landing_page_enabled;
    settings->trust_proxy_headers = trust_proxy_headers;
    settings->udp_enabled = udp_enabled;
    settings->tcp_port_enabled = tcp_enabled;

    global_relay_identity = portillia_relay_identity_load_or_create(identity_path, root_hostname);
    if (!global_relay_identity) {
        LOG_ERROR("failed to load or create relay identity at %s", identity_path);
    } else {
        LOG_INFO("relay identity loaded address=%s name=%s",
                 global_relay_identity->address ? global_relay_identity->address : "",
                 global_relay_identity->name ? global_relay_identity->name : "");
    }

    extern void portillia_server_setup(const char *root_hostname, int api_port, int sni_port, portillia_settings *s);
    extern void portillia_proxy_init_telemetry();
    portillia_proxy_init_telemetry();
    portillia_server_setup(root_hostname, api_port, sni_port, settings);

    // Initialize Multiplexer
    // No global event loop used after refactoring

    cwist_app *app = cwist_app_create();

    char acme_cert_path[1024] = {0};
    char acme_key_path[1024] = {0};

    if (strlen(root_hostname) > 0) {
        portillia_acme_manager *acme = portillia_acme_manager_new(acme_cfg);
        if (acme) {
            global_acme_manager = acme;
            char *cert_file = NULL, *key_file = NULL;
            if (portillia_acme_manager_ensure_certificate(acme, &cert_file, &key_file) == CWIST_SUCCESS) {
                LOG_INFO("Using certificate: %s", cert_file);
                if (cert_file) snprintf(acme_cert_path, sizeof(acme_cert_path), "%s", cert_file);
                if (key_file) snprintf(acme_key_path, sizeof(acme_key_path), "%s", key_file);
                free(cert_file); free(key_file);

                LOG_INFO("Skipping ECH setup because the linked OpenSSL build does not support server ECH");
            }
            portillia_acme_manager_sync_dns(acme);
            if (acme_cfg.ens_gasless_enabled) portillia_acme_manager_sync_ens_gasless(acme);

            pthread_t acme_tid;
            pthread_create(&acme_tid, NULL, acme_renewal_thread, NULL);
            pthread_detach(acme_tid);
        }
    }

    cwist_app_get(app, "/", fallback_spa_handler_clean);
    cwist_app_get(app, "/portal.html", fallback_spa_handler_clean);
    cwist_app_set_error_handler(app, spa_error_handler);
    
    extern void portillia_api_server_setup(cwist_app *app);
    portillia_api_server_setup(app);
    portillia_api_server_relay_setup(app);
    portillia_server_set_keyless_url(public_relay_url ? public_relay_url : portal_url);
    portillia_keyless_server_setup(app, identity_path);
    
    const char *static_dir = getenv("STATIC_DIR") ? getenv("STATIC_DIR") : "cmd/relay-server/dist/app";
    char assets_dir[1024];
    snprintf(assets_dir, sizeof(assets_dir), "%s/assets", static_dir);
    cwist_app_static(app, "/assets", assets_dir);
    
    listener_args *sni_args = malloc(sizeof(listener_args));
    sni_args->sni_port = sni_port;
    sni_args->api_port = api_port;
    
    char cert_path[1024], key_path[1024];
    if (acme_cert_path[0] && acme_key_path[0]) {
        snprintf(cert_path, sizeof(cert_path), "%s", acme_cert_path);
        snprintf(key_path, sizeof(key_path), "%s", acme_key_path);
    } else {
        snprintf(cert_path, sizeof(cert_path), "%s/fullchain.pem", identity_path);
        snprintf(key_path, sizeof(key_path), "%s/privatekey.pem", identity_path);
    }
    /* Terminate TLS at the API server (4017) instead of proxying through
     * an OpenSSL pump on 443. Port 443 then becomes a raw TCP splice that
     * forwards the original ClientHello straight to the API listener. */
    cwist_error_t https_err = cwist_app_use_https(app, cert_path, key_path);
    if (https_err.errtype == CWIST_ERR_INT16 && https_err.error.err_i16 == 0) {
        LOG_INFO("API server HTTPS enabled cert=%s port=%d", cert_path, api_port);
    } else {
        LOG_WARN("API server HTTPS enable failed cert=%s key=%s errtype=%d", cert_path, key_path, https_err.errtype);
    }
    
    discovery_config *disc_cfg = malloc(sizeof(discovery_config));
    disc_cfg->relay_url = strdup(public_relay_url ? public_relay_url : portal_url);
    disc_cfg->advertise_url = strdup(public_relay_url ? public_relay_url : portal_url);
    char *resolved_bootstraps = resolve_portal_relay_urls(bootstraps, discovery_enabled, public_relay_url ? public_relay_url : portal_url);
    disc_cfg->bootstrap_urls = resolved_bootstraps;
    disc_cfg->relay_set = portillia_relay_set_create(NULL, 0);
    disc_cfg->wireguard_port = wg_port;
    disc_cfg->max_routing = max_routing;
    global_disc_cfg = disc_cfg;
    if (disc_cfg->bootstrap_urls) {
        LOG_INFO("discovery bootstraps=%s", disc_cfg->bootstrap_urls);
    } else {
        LOG_WARN("discovery no bootstraps configured");
    }
    portillia_discovery_publish_self(disc_cfg);

    pthread_t sni_tid, wg_tid, disc_tid;
    pthread_create(&sni_tid, NULL, sni_listener_thread, sni_args);
    pthread_create(&wg_tid, NULL, wg_listener_thread, &wg_port);
    if (discovery_enabled) {
        pthread_create(&disc_tid, NULL, discovery_maintenance_loop, disc_cfg);
    }

    // Initialize overlay / hop mux via Rust bridge
    if (global_relay_identity && global_relay_identity->wireguard_private_key && global_relay_identity->wireguard_public_key) {
        if (OverlayInit(global_relay_identity->wireguard_private_key, global_relay_identity->wireguard_public_key, wg_port) == 0) {
            LOG_INFO("overlay initialized via bridge wg_public_key=%s wg_port=%d", global_relay_identity->wireguard_public_key, wg_port);
            pthread_t hop_tid;
            pthread_create(&hop_tid, NULL, hop_accept_thread, NULL);
            pthread_detach(hop_tid);
        } else {
            LOG_ERROR("overlay initialization failed");
        }
    } else {
        LOG_WARN("no wireguard keys available, overlay disabled");
    }

    if (public_relay_url) {
        free(public_relay_url);
    }

    if (udp_enabled) {
        LOG_INFO(
            "relay server started acme_dns_provider=%s api_addr=127.0.0.1:%d discovery_enabled=%s internal_quic_backhaul_addr=[::]:%d max_port=%d min_port=%d multihop_enabled=true pprof_enabled=%s root_host=%s sni_addr=[::]:%d tcp_enabled=%s udp_enabled=%s wireguard_enabled=true",
            acme_dns_provider,
            api_port,
            bool_str(discovery_enabled),
            sni_port,
            max_port,
            min_port,
            bool_str(pprof_enabled),
            root_hostname,
            sni_port,
            bool_str(tcp_enabled),
            bool_str(udp_enabled)
        );
    } else {
        LOG_INFO(
            "relay server started acme_dns_provider=%s api_addr=127.0.0.1:%d discovery_enabled=%s max_port=%d min_port=%d multihop_enabled=true pprof_enabled=%s root_host=%s sni_addr=[::]:%d tcp_enabled=%s udp_enabled=%s wireguard_enabled=true",
            acme_dns_provider,
            api_port,
            bool_str(discovery_enabled),
            max_port,
            min_port,
            bool_str(pprof_enabled),
            root_hostname,
            sni_port,
            bool_str(tcp_enabled),
            bool_str(udp_enabled)
        );
    }

    extern void portillia_quic_backhaul_start(int port);
    portillia_quic_backhaul_start(api_port);
    
    cwist_app_listen(app, api_port);
    return 0;
}
