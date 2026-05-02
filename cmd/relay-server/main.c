#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <portillia/types/types.h>
#include <portillia/utils/log.h>
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
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(fd, 10);
    LOG_INFO("SNI listener started on port %d", port);
    while (1) {
        int client = accept(fd, NULL, NULL);
        if (client < 0) continue;
        const char *sni = get_sni_hostname(client);
        if (sni) LOG_INFO("SNI Hostname: %s", sni);
        close(client);
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
 * @brief Function index_handler
 * @param req Parameter description
 * @param res Parameter description
 * @return void result
 */
void index_handler(cwist_http_request *req, cwist_http_response *res) {
    (void)req;
    cwist_sstring_assign(res->body, "Portal Relay Server (C Implementation)");
}

/**
 * @brief Function main
 * @return int result
 */
int main(void) {
    LOG_INFO("Starting Portal Relay Server (C Implementation)...");
    cwist_app *app = cwist_app_create();
    cwist_app_get(app, "/", index_handler);
    extern void portillia_api_server_setup(cwist_app *app);
    portillia_api_server_setup(app);

    int api_port = 4017, sni_port = 443, wg_port = 51820;
    pthread_t sni_tid, wg_tid;
    pthread_create(&sni_tid, NULL, sni_listener_thread, &sni_port);
    pthread_create(&wg_tid, NULL, wg_listener_thread, &wg_port);
    
    LOG_INFO("API server listening on port %d", api_port);
    cwist_app_listen(app, api_port);
    return 0;
}
