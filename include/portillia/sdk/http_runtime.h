/** @file http_runtime.h
 * @brief Minimal HTTP runtime for portillia exposure.
 *
 * C port of portal-tunnel/sdk/http.go.  Provides a local HTTP server
 * that accepts connections from portillia_exposure_accept() and proxies
 * them to upstream targets according to a route table.
 */
#ifndef PORTILLIA_SDK_HTTP_RUNTIME_H
#define PORTILLIA_SDK_HTTP_RUNTIME_H

#include <portillia/sdk/expose.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct portillia_http_server portillia_http_server_t;

/**
 * @brief Start an HTTP server on local_addr that proxies accepted
 * connections through the given route table.
 *
 * Blocks until the server is shut down or the exposure is closed.
 * @return 0 on clean shutdown, -1 on error.
 */
int portillia_http_server_run_routes(portillia_exposure_t *e,
                                     const portillia_http_route_t *routes,
                                     size_t routes_count,
                                     const char *local_addr);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_SDK_HTTP_RUNTIME_H */
