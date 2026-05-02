#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <cwist/core/utils/json_builder.h>
#include <portillia/types/types.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Function handle_register
 * @param req Parameter description
 * @param res Parameter description
 * @return void result
 */
void handle_register(cwist_http_request *req, cwist_http_response *res) {
    // Basic registration handler
    cwist_sstring_assign(res->body, "{\"ok\": true, \"data\": {\"hostname\": \"demo.portal.dev\", \"access_token\": \"dummy-token\"}}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function handle_discovery
 * @param req Parameter description
 * @param res Parameter description
 * @return void result
 */
void handle_discovery(cwist_http_request *req, cwist_http_response *res) {
    cwist_sstring_assign(res->body, "{\"ok\": true, \"data\": {\"relays\": []}}");
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/**
 * @brief Function portillia_api_server_setup
 * @param app Parameter description
 * @return void result
 */
void portillia_api_server_setup(cwist_app *app) {
    cwist_app_post(app, "/api/v2/register", handle_register);
    cwist_app_get(app, "/api/v2/discovery", handle_discovery);
}
