#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include <portillia/utils/log.h>

typedef struct {
    int port;
} quic_args;

extern void portillia_registry_offer_conn(const char *hostname, int sdk_fd);

#include <poll.h>
#include <cwist/net/yamux.h>

void handle_quic_data_pump(int quic_fd, int target_udp_fd, struct sockaddr_in *target_addr, cwist_yamux_session_t *session) {
    struct pollfd fds[2];
    fds[0].fd = quic_fd;
    fds[0].events = POLLIN;
    fds[1].fd = target_udp_fd;
    fds[1].events = POLLIN;

    uint8_t buf[4096];
    LOG_INFO("QUIC: Starting multiplexed data pump");
    
    while (1) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) break;

        // Receive from QUIC (to local UDP)
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(quic_fd, buf, sizeof(buf));
            if (n > 0) {
                // Yamux de-encapsulation (simplified)
                sendto(target_udp_fd, buf, n, 0, (struct sockaddr *)target_addr, sizeof(*target_addr));
                // Update window if needed
                cwist_yamux_send_window_update(session, 1, n);
            }
        }

        // Receive from Local UDP (to QUIC)
        if (fds[1].revents & POLLIN) {
            ssize_t n = recvfrom(target_udp_fd, buf, sizeof(buf), 0, NULL, NULL);
            if (n > 0) {
                // Yamux encapsulation
                yamux_header_t hdr = { .type = YAMUX_TYPE_DATA, .stream_id = 1, .length = (uint32_t)n };
                write(quic_fd, &hdr, sizeof(hdr));
                write(quic_fd, buf, n);
            }
        }
    }
}

void handle_quic_control(const uint8_t *payload, size_t len, struct sockaddr_in *client_addr) {
    cJSON *root = cJSON_Parse((const char *)payload);
    if (root) {
        cJSON *token = cJSON_GetObjectItem(root, "access_token");
        if (token && token->valuestring) {
            LOG_INFO("QUIC: Access granted for token: %s", token->valuestring);
            // On success, start the data pump
            // handle_quic_data_pump(...);
        }
        cJSON_Delete(root);
    }
}

void *quic_listener_thread(void *arg) {
    quic_args *args = (quic_args *)arg;
    int port = args->port;
    free(args);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("QUIC Backhaul: Failed to bind to port %d", port);
        return NULL;
    }

    while (1) {
        uint8_t buf[4096];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_len);
        if (n > 0) {
            handle_quic_control(buf, n, &client_addr);
        }
    }
    return NULL;
}

void portillia_quic_backhaul_start(int port) {
    pthread_t tid;
    quic_args *args = malloc(sizeof(quic_args));
    args->port = port;
    pthread_create(&tid, NULL, quic_listener_thread, args);
    pthread_detach(tid);
}
