#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <cwist/core/utils/json_builder.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/portal/settings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

extern void portillia_registry_register(const char *hostname, const char *identity_key, int64_t bps_limit);
extern void portillia_registry_register_hop(const char *hop_token, const char *next_ipv4, const char *next_token, const char *identity_key);
extern void portillia_registry_offer_conn(const char *hostname, int sdk_fd);
extern char* portillia_registry_to_json();
extern portillia_settings* portillia_server_get_settings();

extern int portillia_network_ip_in_cidr(const char *ip, const char *cidr);

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
            cJSON *bps_limit = cJSON_GetObjectItem(root, "bps_limit");
            
            cJSON *udp_enabled = cJSON_GetObjectItem(root, "udp_enabled");
            cJSON *tcp_enabled = cJSON_GetObjectItem(root, "tcp_enabled");
            
            if (identity && identity->valuestring) {
                int64_t limit = bps_limit ? (int64_t)bps_limit->valuedouble : 0;
                bool udp = udp_enabled ? cJSON_IsTrue(udp_enabled) : false;
                bool tcp = tcp_enabled ? cJSON_IsTrue(tcp_enabled) : true;

                if (name && name->valuestring) {
                    LOG_INFO("Registering lease for %s (bps_limit=%ld, udp=%d, tcp=%d)", name->valuestring, limit, udp, tcp);
                    portillia_registry_register(name->valuestring, identity->valuestring, limit);
                    
                    cJSON *data = cJSON_CreateObject();
                    cJSON_AddStringToObject(data, "hostname", name->valuestring);
                    cJSON_AddStringToObject(data, "access_token", "dummy-token");
                    cJSON_AddBoolToObject(data, "udp_enabled", udp);
                    cJSON_AddBoolToObject(data, "tcp_enabled", tcp);
                    
                    if (udp) {
                        cJSON_AddNumberToObject(data, "sni_port", 443);
                        cJSON_AddStringToObject(data, "udp_addr", "localhost:51820"); // Simplified
                    }
                    if (tcp) {
                        cJSON_AddStringToObject(data, "tcp_addr", "localhost:4017"); // Simplified
                    }
                    
                    cJSON *res_root = cJSON_CreateObject();
                    cJSON_AddBoolToObject(res_root, "ok", true);
                    cJSON_AddItemToObject(res_root, "data", data);
                    
                    char *res_json = cJSON_PrintUnformatted(res_root);
                    cwist_sstring_assign(res->body, res_json);
                    free(res_json);
                    cJSON_Delete(res_root);
                }
            } else {
                res->status_code = CWIST_HTTP_BAD_REQUEST;
                cwist_sstring_assign(res->body, "{\"ok\": false, \"error\": \"missing fields\"}");
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
    char *host = cwist_http_header_get(req->headers, "X-Portal-Hostname");
    if (!host) host = cwist_http_header_get(req->headers, "Host");
    if (!host) { res->status_code = CWIST_HTTP_BAD_REQUEST; return; }

    const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    send(req->client_fd, resp, strlen(resp), 0);
    req->upgraded = true;
    portillia_registry_offer_conn(host, req->client_fd);
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
    cwist_sstring_assign(res->body, "{\"ok\": true, \"data\": {\"relays\": []}}");
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
    // Return the root domain
    portillia_settings *s = portillia_server_get_settings();
    cwist_sstring_assign(res->body, "{\"ok\": true, \"data\": {\"domain\": \"localhost\"}}");
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
            if (id_obj) {
                const char *addr = cJSON_GetObjectItem(id_obj, "address")->valuestring;
                char msg[2048];
                snprintf(msg, sizeof(msg), 
                    "localhost wants you to sign in with your Ethereum account:\n"
                    "%s\n\n"
                    "Register a portal lease\n\n"
                    "URI: http://localhost/sdk/register\n"
                    "Version: 1\n"
                    "Chain ID: 1\n"
                    "Nonce: %s\n"
                    "Issued At: 2026-05-04T00:00:00Z", addr, "12345678");
                
                cJSON *root = cJSON_CreateObject();
                cJSON *data = cJSON_CreateObject();
                cJSON_AddStringToObject(data, "challenge_id", "rch_mock");
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
    cwist_sstring_assign(res->body, "{\"ok\": true, \"data\": {\"expires_at\": 0, \"access_token\": \"new-token\"}}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_unregister
 */
void handle_unregister(cwist_http_request *req, cwist_http_response *res) {
    cwist_sstring_assign(res->body, "{\"ok\": true}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_healthz
 */
void handle_healthz(cwist_http_request *req, cwist_http_response *res) {
    cwist_sstring_assign(res->body, "{\"status\": \"ok\"}");
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
