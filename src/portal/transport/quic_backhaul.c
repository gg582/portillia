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

void handle_quic_data_pump(int quic_fd, struct sockaddr_in *target_addr) {
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    LOG_INFO("QUIC: Starting data pump for UDP tunnel");
    
    // In Go, this is handled by datagram_relay.go.
    // We bridge the QUIC "connection" (logical) with a real local UDP socket.
    
    uint8_t buf[4096];
    while (1) {
        // Mock: Forward received quic_fd data to local UDP port
        ssize_t n = read(quic_fd, buf, sizeof(buf));
        if (n <= 0) break;
        sendto(udp_fd, buf, n, 0, (struct sockaddr *)target_addr, sizeof(*target_addr));
        
        // And vice-versa
    }
    close(udp_fd);
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

    LOG_INFO("QUIC Backhaul listener active on port %d", port);
    
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