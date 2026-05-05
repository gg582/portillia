/** @file http_runtime.c
 * @brief Minimal HTTP runtime for portillia exposure.
 *
 * C port of portal-tunnel/sdk/http.go.  Provides a local HTTP server
 * that accepts connections from portillia_exposure_accept() and proxies
 * them to upstream targets according to a route table.
 *
 * NOTE: This is a minimal implementation.  Compression, cookie rewriting,
 * and advanced header manipulation are omitted for now.
 */

#include <portillia/sdk/http_runtime.h>
#include <portillia/sdk/expose.h>
#include <portillia/utils/log.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HTTP_BUFSIZE 8192
#define MAX_HEADERS 64

typedef struct {
    char *name;
    char *value;
} http_header_t;

typedef struct {
    char method[16];
    char path[2048];
    char version[16];
    http_header_t headers[MAX_HEADERS];
    size_t header_count;
    size_t content_length;
} http_request_t;

typedef struct {
    int status;
    char reason[32];
    http_header_t headers[MAX_HEADERS];
    size_t header_count;
    size_t content_length;
} http_response_t;

typedef struct {
    char *prefix;
    size_t prefix_len;
    char *upstream_host;
    int upstream_port;
    char *upstream_path;
} proxy_route_t;

typedef struct {
    portillia_exposure_t *exposure;
    proxy_route_t *routes;
    size_t route_count;
    int listen_fd;
    bool shutdown;
    pthread_t thread;
} http_server_ctx_t;

/* ---------- Helpers ---------- */

static void free_request(http_request_t *req) {
    if (!req) return;
    for (size_t i = 0; i < req->header_count; i++) {
        free(req->headers[i].name);
        free(req->headers[i].value);
    }
}

static void free_response(http_response_t *resp) {
    if (!resp) return;
    for (size_t i = 0; i < resp->header_count; i++) {
        free(resp->headers[i].name);
        free(resp->headers[i].value);
    }
}

static ssize_t recv_line(int fd, char *buf, size_t max) {
    size_t i = 0;
    while (i < max - 1) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return n;
        buf[i++] = c;
        if (i >= 2 && buf[i - 2] == '\r' && buf[i - 1] == '\n') {
            buf[i - 2] = '\0';
            return (ssize_t)i;
        }
    }
    buf[i] = '\0';
    return (ssize_t)i;
}

static int parse_request(int fd, http_request_t *req) {
    memset(req, 0, sizeof(*req));
    char line[4096];
    ssize_t n = recv_line(fd, line, sizeof(line));
    if (n <= 0) return -1;

    if (sscanf(line, "%15s %2047s %15s", req->method, req->path, req->version) != 3) {
        return -1;
    }

    while (req->header_count < MAX_HEADERS) {
        n = recv_line(fd, line, sizeof(line));
        if (n <= 0) return -1;
        if (line[0] == '\0') break; /* empty line -> end of headers */

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *name = line;
        char *value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;

        req->headers[req->header_count].name = strdup(name);
        req->headers[req->header_count].value = strdup(value);
        if (strcasecmp(name, "Content-Length") == 0) {
            req->content_length = (size_t)strtoul(value, NULL, 10);
        }
        req->header_count++;
    }
    return 0;
}

static int parse_response(int fd, http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));
    char line[4096];
    ssize_t n = recv_line(fd, line, sizeof(line));
    if (n <= 0) return -1;

    char version[16];
    if (sscanf(line, "%15s %d %31s", version, &resp->status, resp->reason) < 2) {
        return -1;
    }

    while (resp->header_count < MAX_HEADERS) {
        n = recv_line(fd, line, sizeof(line));
        if (n <= 0) return -1;
        if (line[0] == '\0') break;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *name = line;
        char *value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;

        resp->headers[resp->header_count].name = strdup(name);
        resp->headers[resp->header_count].value = strdup(value);
        if (strcasecmp(name, "Content-Length") == 0) {
            resp->content_length = (size_t)strtoul(value, NULL, 10);
        }
        resp->header_count++;
    }
    return 0;
}

static const char *get_header(const http_header_t *headers, size_t count, const char *name) {
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(headers[i].name, name) == 0) return headers[i].value;
    }
    return NULL;
}

static void write_headers(int fd, const http_header_t *headers, size_t count) {
    for (size_t i = 0; i < count; i++) {
        char buf[4096];
        int n = snprintf(buf, sizeof(buf), "%s: %s\r\n", headers[i].name, headers[i].value);
        if (n > 0) send(fd, buf, (size_t)n, MSG_NOSIGNAL);
    }
}

static int connect_upstream(const char *host, int port) {
    struct hostent *server = gethostbyname(host);
    if (!server) { errno = EHOSTUNREACH; return -1; }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    memcpy(&addr.sin_addr.s_addr, server->h_addr, (size_t)server->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

static int parse_upstream_url(const char *url, char *host, size_t host_len, int *port, char *path, size_t path_len) {
    (void)host_len;
    (void)path_len;
    *port = 80;
    if (sscanf(url, "http://%255[^:/]:%d%2047s", host, port, path) >= 1) return 0;
    if (sscanf(url, "http://%255[^/]%2047s", host, path) == 2) return 0;
    if (sscanf(url, "http://%255s", host) == 1) { path[0] = '/'; path[1] = '\0'; return 0; }
    return -1;
}

static proxy_route_t *find_route(proxy_route_t *routes, size_t count, const char *path) {
    proxy_route_t *best = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < count; i++) {
        size_t prefix_len = routes[i].prefix_len;
        if (prefix_len > best_len && strncmp(path, routes[i].prefix, prefix_len) == 0) {
            best = &routes[i];
            best_len = prefix_len;
        }
    }
    return best;
}

/* ---------- Proxy handler ---------- */

static void handle_client(http_server_ctx_t *srv, int client_fd) {
    http_request_t req = {0};
    if (parse_request(client_fd, &req) != 0) {
        close(client_fd);
        return;
    }

    proxy_route_t *route = find_route(srv->routes, srv->route_count, req.path);
    if (!route) {
        const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(client_fd, not_found, strlen(not_found), MSG_NOSIGNAL);
        free_request(&req);
        close(client_fd);
        return;
    }

    /* Rewrite path */
    char upstream_path[2048];
    snprintf(upstream_path, sizeof(upstream_path), "%s%s",
             route->upstream_path, req.path + route->prefix_len);

    int upstream_fd = connect_upstream(route->upstream_host, route->upstream_port);
    if (upstream_fd < 0) {
        const char *bad_gw = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(client_fd, bad_gw, strlen(bad_gw), MSG_NOSIGNAL);
        free_request(&req);
        close(client_fd);
        return;
    }

    /* Forward request line */
    char req_line[4096];
    int req_line_len = snprintf(req_line, sizeof(req_line), "%s %s %s\r\n",
                                  req.method, upstream_path, req.version);
    send(upstream_fd, req_line, (size_t)req_line_len, MSG_NOSIGNAL);

    /* Forward headers */
    write_headers(upstream_fd, req.headers, req.header_count);
    send(upstream_fd, "\r\n", 2, MSG_NOSIGNAL);

    /* Forward body */
    if (req.content_length > 0) {
        char buf[HTTP_BUFSIZE];
        size_t remaining = req.content_length;
        while (remaining > 0) {
            size_t to_read = remaining < sizeof(buf) ? remaining : sizeof(buf);
            ssize_t n = recv(client_fd, buf, to_read, 0);
            if (n <= 0) break;
            send(upstream_fd, buf, (size_t)n, MSG_NOSIGNAL);
            remaining -= (size_t)n;
        }
    }

    /* Read response */
    http_response_t resp = {0};
    if (parse_response(upstream_fd, &resp) != 0) {
        const char *bad_gw = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(client_fd, bad_gw, strlen(bad_gw), MSG_NOSIGNAL);
        close(upstream_fd);
        free_request(&req);
        close(client_fd);
        return;
    }

    /* Write response line */
    char resp_line[256];
    int resp_line_len = snprintf(resp_line, sizeof(resp_line), "%s %d %s\r\n",
                                   req.version, resp.status, resp.reason);
    send(client_fd, resp_line, (size_t)resp_line_len, MSG_NOSIGNAL);

    /* Write headers */
    write_headers(client_fd, resp.headers, resp.header_count);
    send(client_fd, "\r\n", 2, MSG_NOSIGNAL);

    /* Write body */
    if (resp.content_length > 0) {
        char buf[HTTP_BUFSIZE];
        size_t remaining = resp.content_length;
        while (remaining > 0) {
            size_t to_read = remaining < sizeof(buf) ? remaining : sizeof(buf);
            ssize_t n = recv(upstream_fd, buf, to_read, 0);
            if (n <= 0) break;
            send(client_fd, buf, (size_t)n, MSG_NOSIGNAL);
            remaining -= (size_t)n;
        }
    } else {
        /* Transfer response until upstream closes or we hit a reasonable limit */
        char buf[HTTP_BUFSIZE];
        ssize_t n;
        while ((n = recv(upstream_fd, buf, sizeof(buf), 0)) > 0) {
            send(client_fd, buf, (size_t)n, MSG_NOSIGNAL);
        }
    }

    close(upstream_fd);
    free_request(&req);
    free_response(&resp);
    close(client_fd);
}

static void *accept_loop_thread(void *arg) {
    http_server_ctx_t *srv = (http_server_ctx_t *)arg;
    while (!srv->shutdown) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(srv->listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        handle_client(srv, client_fd);
    }
    return NULL;
}

/* ---------- Public API ---------- */

int portillia_http_server_run_routes(portillia_exposure_t *e,
                                     const portillia_http_route_t *routes,
                                     size_t routes_count,
                                     const char *local_addr) {
    if (!e || !routes || routes_count == 0 || !local_addr) {
        errno = EINVAL;
        return -1;
    }

    /* Parse local address */
    char host[256] = {0};
    int port = 8080;
    if (sscanf(local_addr, "%255[^:]:%d", host, &port) < 1) {
        strncpy(host, local_addr, sizeof(host) - 1);
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return -1;

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (host[0] && strcmp(host, "0.0.0.0") != 0) {
        struct hostent *h = gethostbyname(host);
        if (h) memcpy(&addr.sin_addr.s_addr, h->h_addr, (size_t)h->h_length);
    }

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        return -1;
    }
    if (listen(listen_fd, 128) < 0) {
        close(listen_fd);
        return -1;
    }

    /* Build route table */
    proxy_route_t *proxy_routes = (proxy_route_t *)calloc(routes_count, sizeof(proxy_route_t));
    if (!proxy_routes) {
        close(listen_fd);
        errno = ENOMEM;
        return -1;
    }
    for (size_t i = 0; i < routes_count; i++) {
        proxy_routes[i].prefix = routes[i].path ? strdup(routes[i].path) : strdup("/");
        proxy_routes[i].prefix_len = strlen(proxy_routes[i].prefix);
        char uhost[256] = {0};
        char upath[2048] = {0};
        int uport = 80;
        if (routes[i].upstream && parse_upstream_url(routes[i].upstream, uhost, sizeof(uhost), &uport, upath, sizeof(upath)) == 0) {
            proxy_routes[i].upstream_host = strdup(uhost);
            proxy_routes[i].upstream_port = uport;
            proxy_routes[i].upstream_path = strdup(upath);
        } else {
            proxy_routes[i].upstream_host = strdup("localhost");
            proxy_routes[i].upstream_port = 80;
            proxy_routes[i].upstream_path = strdup("/");
        }
    }

    /* Sort routes by prefix length descending (longest prefix first) */
    for (size_t i = 0; i < routes_count; i++) {
        for (size_t j = i + 1; j < routes_count; j++) {
            if (proxy_routes[j].prefix_len > proxy_routes[i].prefix_len) {
                proxy_route_t tmp = proxy_routes[i];
                proxy_routes[i] = proxy_routes[j];
                proxy_routes[j] = tmp;
            }
        }
    }

    http_server_ctx_t srv = {
        .exposure = e,
        .routes = proxy_routes,
        .route_count = routes_count,
        .listen_fd = listen_fd,
        .shutdown = false,
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, accept_loop_thread, &srv) != 0) {
        close(listen_fd);
        for (size_t i = 0; i < routes_count; i++) {
            free(proxy_routes[i].prefix);
            free(proxy_routes[i].upstream_host);
            free(proxy_routes[i].upstream_path);
        }
        free(proxy_routes);
        return -1;
    }

    /* Block until exposure is closed */
    while (!atomic_load(&e->cancelled) && !srv.shutdown) {
        sleep(1);
    }

    srv.shutdown = true;
    close(listen_fd);
    pthread_join(tid, NULL);

    for (size_t i = 0; i < routes_count; i++) {
        free(proxy_routes[i].prefix);
        free(proxy_routes[i].upstream_host);
        free(proxy_routes[i].upstream_path);
    }
    free(proxy_routes);
    return 0;
}
