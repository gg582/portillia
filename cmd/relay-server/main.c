#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/portal/acme/manager.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <wireguard_proto.h>

extern const char *get_sni_hostname(int client_fd);

void *sni_listener_thread(void *arg) {
    int port = *(int *)arg;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(fd, 128);
    LOG_INFO("SNI router started on port %d", port);
    
    while (1) {
        int client = accept(fd, NULL, NULL);
        if (client < 0) continue;
        
        char *sni = get_sni_hostname(client);
        if (sni) {
            LOG_INFO("SNI Hostname: %s", sni);
            // In Go: If matches identity, bridge to API. Else, bridge to relay/lease.
            // For parity, let's proxy to localhost:4017 (API) if matching "demo.portal.dev"
            int target_fd = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in target = { .sin_family = AF_INET, .sin_port = htons(4017), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
            if (connect(target_fd, (struct sockaddr *)&target, sizeof(target)) == 0) {
                extern void portillia_proxy_bridge(int client_fd, int target_fd);
                portillia_proxy_bridge(client, target_fd);
            } else {
                close(target_fd);
                close(client);
            }
            free(sni);
        } else {
            close(client);
        }
    }
    return NULL;
}

void *wg_listener_thread(void *arg) {
    int port = *(int *)arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    LOG_INFO("WireGuard listener started on port %d", port);
    while (1) {
        wg_header_t header;
        recvfrom(fd, &header, sizeof(header), 0, NULL, NULL);
        // Process encrypted wireguard packet
    }
    return NULL;
}

/**
 * @brief Simple string replace returning newly allocated memory.
 */
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

void fallback_spa_handler_clean(cwist_http_request *req, cwist_http_response *res) {
    (void)req;
    
    FILE *f = fopen("cmd/relay-server/dist/app/portal.html", "rb");
    if (!f) {
        res->status_code = CWIST_HTTP_NOT_FOUND;
        cwist_sstring_assign(res->body, "Not Found");
        return;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *html = malloc(fsize + 1);
    fread(html, 1, fsize, f);
    fclose(f);
    html[fsize] = 0;
    
    char *head_end = strstr(html, "</head>");
    char *final_html = malloc(fsize + 4096);
    final_html[0] = '\0';
    
    if (head_end) {
        strncat(final_html, html, head_end - html);
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
    
    free(final_html);
    free(r1);
    free(r2);
    free(r3);
    free(r4);
    
    cwist_http_header_add(&res->headers, "Content-Type", "text/html; charset=utf-8");
    cwist_http_header_add(&res->headers, "Cache-Control", "no-cache, must-revalidate");
}

/**
 * @brief Function main
 * @return int result
 */
int main(void) {
    LOG_INFO("Starting Portal Relay Server (C Implementation)...");

    portillia_acme_config acme_cfg = {
        .base_domain = getenv("PORTAL_DOMAIN"),
        .key_dir = getenv("IDENTITY_PATH") ? getenv("IDENTITY_PATH") : ".portal-certs",
        .dns_provider_type = getenv("ACME_DNS_PROVIDER"),
        .ens_gasless_enabled = getenv("ENS_GASLESS_ENABLED") && strcmp(getenv("ENS_GASLESS_ENABLED"), "true") == 0,
        .ens_gasless_address = getenv("ENS_GASLESS_ADDRESS"),
        .cloudflare_token = getenv("CLOUDFLARE_TOKEN"),
        .gcp_project_id = getenv("GCP_PROJECT_ID"),
        .gcp_managed_zone = getenv("GCP_MANAGED_ZONE"),
        .aws_access_key_id = getenv("AWS_ACCESS_KEY_ID"),
        .aws_secret_access_key = getenv("AWS_SECRET_ACCESS_KEY"),
        .aws_session_token = getenv("AWS_SESSION_TOKEN"),
        .aws_region = getenv("AWS_REGION"),
        .aws_hosted_zone_id = getenv("AWS_HOSTED_ZONE_ID"),
        .aws_kms_key_arn = getenv("AWS_DNSSEC_KMS_KEY_ARN")
    };

    if (acme_cfg.base_domain) {
        portillia_acme_manager *acme = portillia_acme_manager_new(acme_cfg);
        if (acme) {
            char *cert_file = NULL, *key_file = NULL;
            if (portillia_acme_manager_ensure_certificate(acme, &cert_file, &key_file) == CWIST_SUCCESS) {
                LOG_INFO("Using certificate: %s", cert_file);
                free(cert_file);
                free(key_file);
            }
            portillia_acme_manager_sync_dns(acme);
            if (acme_cfg.ens_gasless_enabled) {
                portillia_acme_manager_sync_ens_gasless(acme);
            }
            // In a real server, we might want to keep the manager for background renewal
            // but for this implementation, we just sync at startup.
            // portillia_acme_manager_destroy(acme); 
        }
    }

    cwist_app *app = cwist_app_create();
    
    // Explicitly mount SPA fallback for routes that aren't APIs and aren't found in static assets.
    cwist_app_get(app, "/", fallback_spa_handler_clean);
    cwist_app_get(app, "/portal.html", fallback_spa_handler_clean);
    
    extern void portillia_api_server_setup(cwist_app *app);
    portillia_api_server_setup(app);

    // Serve static files from the built frontend directory. 
    // Important: cwist processes static directories BEFORE exact routes if it matches a file.
    // So assets/xxx.css will be served naturally if we mount the static dir at "/"
    cwist_app_static(app, "/", "cmd/relay-server/dist/app");

    int api_port = 4017, sni_port = 443, wg_port = 51820;
    pthread_t sni_tid, wg_tid;
    pthread_create(&sni_tid, NULL, sni_listener_thread, &sni_port);
    pthread_create(&wg_tid, NULL, wg_listener_thread, &wg_port);
    
    LOG_INFO("API server listening on port %d", api_port);
    cwist_app_listen(app, api_port);
    return 0;
}
