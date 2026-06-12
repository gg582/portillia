#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Function demo_handler
 * @param req Parameter description
 * @param res Parameter description
 * @return void result
 */
void demo_handler(cwist_http_request *req, cwist_http_response *res) {
    (void)req;
    cwist_sstring_assign(res->body, "<h1>Portal Demo App (C)</h1><p>Relay connectivity verified!</p>");
    cwist_http_header_add(&res->headers, "Content-Type", "text/html");
}

/**
 * @brief Function main
 * @param argc Parameter description
 * @param argv Parameter description
 * @return int result
 */
int main(int argc, char **argv) {
    portillia_manifest_init();
    LOG_INFO("Starting Portal Demo App (C Implementation)...");
    
    // In a real implementation, this would use the SDK to expose itself
    // For now, it just starts a local web server
    
    cwist_app *app = cwist_app_create();
    cwist_app_get(app, "/", demo_handler);
    
    int port = 8092;
    LOG_INFO("Listening on port %d", port);
    cwist_app_listen(app, port);
    cwist_app_destroy(app);
    
    return 0;
}
