#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <cwist/core/utils/json_builder.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <cjson/cJSON.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include <portillia/portal/discovery/discovery.h>
#include "portal_bridge.h"

extern discovery_config *global_disc_cfg;

void handle_discovery_announce(cwist_http_request *req, cwist_http_response *res) {
    cwist_sstring_assign(res->body, "{\"ok\": true, \"data\": {\"protocol_version\": \"7\", \"accepted\": false}}");
    if (req->body && req->body->size > 0) {
        cJSON *root = cJSON_Parse(req->body->data);
        if (root) {
            cJSON *desc = cJSON_GetObjectItem(root, "descriptor");
            if (desc && global_disc_cfg && global_disc_cfg->relay_set) {
                cJSON *api_addr = cJSON_GetObjectItem(desc, "api_https_addr");
                if (api_addr && api_addr->valuestring) {
                    /* Verify descriptor signature via Go bridge before accepting */
                    char *desc_json = cJSON_PrintUnformatted(desc);
                    bool verified = false;
                    if (desc_json) {
                        char *verified_json = VerifyDescriptorJSON(desc_json);
                        if (verified_json) {
                            verified = true;
                            FreeCString(verified_json);
                        }
                        free(desc_json);
                    }

                    if (!verified) {
                        LOG_WARN("relay discovery announce rejected: invalid descriptor signature relay=%s", api_addr->valuestring);
                        cJSON_Delete(root);
                        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
                        return;
                    }

                    portillia_relay_descriptor d = {0};
                    cJSON *addr = cJSON_GetObjectItem(desc, "address");
                    cJSON *version = cJSON_GetObjectItem(desc, "version");
                    cJSON *issued = cJSON_GetObjectItem(desc, "issued_at");
                    cJSON *expires = cJSON_GetObjectItem(desc, "expires_at");
                    cJSON *wg_pub = cJSON_GetObjectItem(desc, "wireguard_public_key");
                    cJSON *wg_port = cJSON_GetObjectItem(desc, "wireguard_port");
                    cJSON *supports_overlay = cJSON_GetObjectItem(desc, "supports_overlay");
                    cJSON *supports_udp = cJSON_GetObjectItem(desc, "supports_udp");
                    cJSON *supports_tcp = cJSON_GetObjectItem(desc, "supports_tcp");
                    cJSON *active_connections = cJSON_GetObjectItem(desc, "active_connections");
                    cJSON *tcp_bps = cJSON_GetObjectItem(desc, "tcp_bps");
                    cJSON *signature = cJSON_GetObjectItem(desc, "signature");
                    d.address = strdup((addr && cJSON_IsString(addr) && addr->valuestring) ? addr->valuestring : "");
                    d.version = strdup((version && cJSON_IsString(version) && version->valuestring) ? version->valuestring : "");
                    d.api_https_addr = strdup(api_addr->valuestring);
                    d.wireguard_public_key = strdup((wg_pub && cJSON_IsString(wg_pub) && wg_pub->valuestring) ? wg_pub->valuestring : "");
                    d.signature = strdup((signature && cJSON_IsString(signature) && signature->valuestring) ? signature->valuestring : "");
                    d.issued_at = (issued && cJSON_IsString(issued) && issued->valuestring) ? time(NULL) : time(NULL);
                    d.expires_at = (expires && cJSON_IsString(expires) && expires->valuestring) ? time(NULL) + 300 : time(NULL) + 300;
                    d.wireguard_port = (wg_port && cJSON_IsNumber(wg_port)) ? wg_port->valueint : 0;
                    d.supports_overlay = supports_overlay ? cJSON_IsTrue(supports_overlay) : false;
                    d.supports_udp = supports_udp ? cJSON_IsTrue(supports_udp) : false;
                    d.supports_tcp = supports_tcp ? cJSON_IsTrue(supports_tcp) : false;
                    d.active_connections = (active_connections && cJSON_IsNumber(active_connections)) ? (int64_t)active_connections->valuedouble : 0;
                    d.tcp_bps = (tcp_bps && cJSON_IsNumber(tcp_bps)) ? tcp_bps->valuedouble : 0.0;

                    portillia_relay_set_upsert(global_disc_cfg->relay_set, d);

                    char *source_ip = cwist_http_header_get(req->headers, "X-Real-IP");
                    if (!source_ip || source_ip[0] == '\0') {
                        source_ip = "127.0.0.1";
                    }
                    LOG_INFO("relay discovery announce accepted relay=%s source_ip=%s", api_addr->valuestring, source_ip);

                    cwist_sstring_assign(res->body, "{\"ok\": true, \"data\": {\"protocol_version\": \"7\", \"accepted\": true}}");
                    free(d.address);
                    free(d.version);
                    free(d.api_https_addr);
                    free(d.wireguard_public_key);
                    free(d.signature);
                }
            }
            cJSON_Delete(root);
        }
    }
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

void portillia_api_server_relay_setup(cwist_app *app) {
    cwist_app_post(app, "/discovery/announce", handle_discovery_announce);
}
