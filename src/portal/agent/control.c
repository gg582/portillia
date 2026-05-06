#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <cwist/core/utils/json_builder.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <portillia/portal/agent/control.h>
#include <cjson/cJSON.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

static void handle_agent_status(cwist_http_request *req, cwist_http_response *res) {
    (void)req;
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "control_addr", "");
    cJSON *tunnels = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "tunnels", tunnels);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    cwist_sstring_assign(res->body, json ? json : "{\"control_addr\":\"\",\"tunnels\":[]}");
    free(json);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

static void handle_agent_shutdown(cwist_http_request *req, cwist_http_response *res) {
    (void)req;
    cwist_sstring_assign(res->body, "{\"accepted\":true}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
    /* Graceful shutdown of the whole process for now (skeleton). */
    exit(0);
}

static void handle_not_implemented(cwist_http_request *req, cwist_http_response *res) {
    (void)req;
    res->status_code = CWIST_HTTP_NOT_IMPLEMENTED;
    cwist_sstring_assign(res->body, "{\"error\":\"not implemented\"}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

int portillia_agent_control_server_run(const char *control_addr) {
    if (!control_addr || !control_addr[0]) control_addr = "127.0.0.1:4019";
    const char *colon = strrchr(control_addr, ':');
    int port = 4019;
    if (colon) {
        port = atoi(colon + 1);
    }
    cwist_app *app = cwist_app_create();
    if (!app) {
        LOG_ERROR("Agent control server: failed to create cwist app");
        return -1;
    }
    cwist_app_get(app, "/v1/agent/status", handle_agent_status);
    cwist_app_post(app, "/v1/agent/shutdown", handle_agent_shutdown);
    cwist_app_post(app, "/v1/agent/tunnels", handle_not_implemented);
    cwist_app_delete(app, "/v1/agent/tunnels/*", handle_not_implemented);
    cwist_app_post(app, "/v1/agent/tunnels/*/relays/seed", handle_not_implemented);
    cwist_app_post(app, "/v1/agent/tunnels/*/multi-hop", handle_not_implemented);
    LOG_INFO("Agent control server listening on %s (port %d)", control_addr, port);
    int rc = cwist_app_listen(app, port);
    cwist_app_destroy(app);
    return rc;
}
