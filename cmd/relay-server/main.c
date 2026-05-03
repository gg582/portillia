#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/portal/acme/manager.h>
#include <portillia/portal/discovery/discovery.h>
#include <portillia/portal/settings.h>
#include <cwist/net/yamux.h>
#include <portillia/portal/api_server_relay.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <wireguard_proto.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>

extern char *get_sni_hostname(int client_fd);
discovery_config *global_disc_cfg = NULL;
portillia_acme_manager *global_acme_manager = NULL;

typedef struct {
    int sni_port;
    int api_port;
} listener_args;

#include <errno.h>
#include <string.h>

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
    LOG_INFO("Unified listener started on port %d", port);
    
    while (1) {
        int client = accept(fd, NULL, NULL);
        if (client < 0) continue;
        
        // Peek at the first few bytes to determine if it's Hop Mux (Yamux) or SNI/TLS
        char peek_buf[4];
        ssize_t n = recv(client, peek_buf, sizeof(peek_buf), MSG_PEEK);
        
        // Yamux magic bytes or specific identification could be used here.
        // For now, assuming if SNI isn't found, try Hop Mux (or use specific protocol headers).
        // The original logic was: if SNI is found -> SNI handler, else -> Hop Mux.
        
        char *sni = get_sni_hostname(client);
        if (sni) {
            LOG_INFO("SNI Hostname: %s", sni);
            extern void portillia_server_handle_connect(const char *hostname, int client_fd);
            portillia_server_handle_connect(sni, client);
            free(sni);
        } else {
            LOG_INFO("No SNI found, falling back to Hop Mux (Yamux)");
            cwist_yamux_session_create(client);
        }
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
    int port = *(int *)arg;
    LOG_INFO("WireGuard controller active on port %d", port);
    
    // In production, we'd listen for discovery updates and call add_wg_peer
    while (1) {
        // Mock event loop for peer discovery
        sleep(60); 
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
    char *r4 = replace_str(r3, "[%RELEASE_VERSION%]", "v2.1.8-c");
    
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

int main(void) {
    portillia_acme_config acme_cfg = {
        .base_domain = getenv("PORTAL_DOMAIN"),
        .key_dir = getenv("IDENTITY_PATH") ? getenv("IDENTITY_PATH") : ".portal-certs",
        .dns_provider_type = getenv("ACME_DNS_PROVIDER"),
        .ens_gasless_enabled = getenv("ENS_GASLESS_ENABLED") && strcmp(getenv("ENS_GASLESS_ENABLED"), "true") == 0,
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

    int api_port = getenv("PORTAL_API_PORT") ? atoi(getenv("PORTAL_API_PORT")) : (getenv("API_PORT") ? atoi(getenv("API_PORT")) : 4017);
    int sni_port = getenv("PORTAL_SNI_PORT") ? atoi(getenv("PORTAL_SNI_PORT")) : (getenv("SNI_PORT") ? atoi(getenv("SNI_PORT")) : 443);
    int wg_port = getenv("PORTAL_WG_PORT") ? atoi(getenv("PORTAL_WG_PORT")) : (getenv("WIREGUARD_PORT") ? atoi(getenv("WIREGUARD_PORT")) : 51820);

    LOG_INFO("configured relay server: release_version=%s, portal_url=%s, identity_path=%s, bootstraps=%s, discovery_enabled=%d, wireguard_port=%d, api_port=%d, sni_port=%d, trust_proxy_headers=%d, trusted_proxy_cidrs=%s, udp_enabled=%d, tcp_enabled=%d, min_port=%d, max_port=%d, landing_page_enabled=%d, headless_shell_enabled=%d, acme_dns_provider=%s, ens_gasless_enabled=%d",
             "v2.1.8-c", acme_cfg.base_domain ? acme_cfg.base_domain : "", acme_cfg.key_dir, "", 0, wg_port, api_port, sni_port, 0, "", 0, 0, 0, 0, 1, 0, acme_cfg.dns_provider_type ? acme_cfg.dns_provider_type : "", acme_cfg.ens_gasless_enabled);

    char settings_path[1024];
    snprintf(settings_path, sizeof(settings_path), "%s/settings.json", acme_cfg.key_dir);
    portillia_settings *settings = portillia_settings_load(settings_path);

    extern void portillia_server_setup(const char *root_hostname, int api_port, int sni_port, portillia_settings *s);
    extern void portillia_proxy_init_telemetry();
    portillia_proxy_init_telemetry();
    portillia_server_setup(acme_cfg.base_domain ? acme_cfg.base_domain : "localhost", api_port, sni_port, settings);

    // Initialize Multiplexer
    // No global event loop used after refactoring

    cwist_app *app = cwist_app_create();

    if (acme_cfg.base_domain) {
        portillia_acme_manager *acme = portillia_acme_manager_new(acme_cfg);
        if (acme) {
            global_acme_manager = acme;
            char *cert_file = NULL, *key_file = NULL;
            if (portillia_acme_manager_ensure_certificate(acme, &cert_file, &key_file) == CWIST_SUCCESS) {
                LOG_INFO("Using certificate: %s", cert_file);
                cwist_app_use_https(app, cert_file, key_file);
                free(cert_file); free(key_file);
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
    
    const char *static_dir = getenv("STATIC_DIR") ? getenv("STATIC_DIR") : "cmd/relay-server/dist/app";
    char assets_dir[1024];
    snprintf(assets_dir, sizeof(assets_dir), "%s/assets", static_dir);
    cwist_app_static(app, "/assets", assets_dir);
    
    listener_args *sni_args = malloc(sizeof(listener_args));
    sni_args->sni_port = sni_port;
    sni_args->api_port = api_port;
    
    discovery_config *disc_cfg = malloc(sizeof(discovery_config));
    disc_cfg->relay_url = getenv("PORTAL_URL") ? strdup(getenv("PORTAL_URL")) : strdup("http://localhost:4017");
    disc_cfg->bootstrap_urls = getenv("BOOTSTRAPS") ? strdup(getenv("BOOTSTRAPS")) : NULL;
    disc_cfg->relay_set = portillia_relay_set_new();
    global_disc_cfg = disc_cfg;

    pthread_t sni_tid, wg_tid, disc_tid;
    pthread_create(&sni_tid, NULL, sni_listener_thread, sni_args);
    pthread_create(&wg_tid, NULL, wg_listener_thread, &wg_port);
    if (disc_cfg->bootstrap_urls) {
        pthread_create(&disc_tid, NULL, discovery_maintenance_loop, disc_cfg);
    }
    
    LOG_INFO("API server listening on port %d", api_port);
    extern void portillia_quic_backhaul_start(int port);
    portillia_quic_backhaul_start(api_port);
    
    cwist_app_listen(app, api_port);
    return 0;
}