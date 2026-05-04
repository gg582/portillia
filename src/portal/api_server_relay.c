#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <cwist/core/utils/json_builder.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <cjson/cJSON.h>
#include <time.h> // For time(NULL)

#include <portillia/portal/discovery/discovery.h>

extern discovery_config *global_disc_cfg;

/**
 * @brief Function handle_discovery_announce
 */
void handle_discovery_announce(cwist_http_request *req, cwist_http_response *res) {
    cwist_sstring_assign(res->body, "{\"protocol_version\": \"7\", \"accepted\": false}");
    if (req->body && req->body->size > 0) {
        cJSON *root = cJSON_Parse(req->body->data);
        if (root) {
            cJSON *desc = cJSON_GetObjectItem(root, "descriptor");
            if (desc && global_disc_cfg && global_disc_cfg->relay_set) {
                cJSON *api_addr = cJSON_GetObjectItem(desc, "api_https_addr");
                if (api_addr && api_addr->valuestring) {
                    portillia_relay_descriptor d = {0};
                    d.api_https_addr = cwist_sstring_create();
                    cwist_sstring_assign(d.api_https_addr, api_addr->valuestring);
                    d.expires_at = time(NULL) + 60;
                    
                    portillia_relay_set_upsert(global_disc_cfg->relay_set, d);

                    char *source_ip = cwist_http_header_get(req->headers, "X-Real-IP");
                    if (!source_ip || source_ip[0] == '\0') {
                        source_ip = "127.0.0.1";
                    }
                    LOG_INFO("relay discovery announce accepted relay=%s source_ip=%s", api_addr->valuestring, source_ip);
                    
                    cwist_sstring_assign(res->body, "{\"protocol_version\": \"7\", \"accepted\": true}");
                    cwist_sstring_destroy(d.api_https_addr);
                }
            }
            cJSON_Delete(root);
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function portillia_api_server_relay_setup
 */
void portillia_api_server_relay_setup(cwist_app *app) {
    cwist_app_post(app, "/discovery/announce", handle_discovery_announce);
}
