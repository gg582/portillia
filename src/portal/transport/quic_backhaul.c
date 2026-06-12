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
#include <poll.h>

typedef struct {
    int port;
} quic_args;

extern void portillia_registry_offer_conn(const char *hostname, int sdk_fd);

/* Minimal yamux-like framing layer used by the QUIC backhaul data pump.
 * The full cwist yamux helpers are no longer linked, so we keep a local,
 * self-contained stub implementation here. */

typedef struct {
    int dummy;
} cwist_yamux_session_t;

typedef enum {
    YAMUX_TYPE_DATA = 0,
    YAMUX_TYPE_WINDOW_UPDATE = 1,
    YAMUX_TYPE_PING = 2,
    YAMUX_TYPE_GOAWAY = 3
} yamux_type_t;

typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;
} yamux_header_t;

void cwist_yamux_send_window_update(cwist_yamux_session_t *session, uint32_t stream_id, uint32_t increment) {
    (void)session;
    (void)stream_id;
    (void)increment;
    /* Local stub: real window bookkeeping would be implemented here.
     * For now the pump runs unidirectionally and relies on socket buffers. */
}

/* Forwards packets between a QUIC-like stream socket and a local UDP target
 * using a simple length-prefixed yamux-style framing. This is intentionally
 * minimal: a production backhaul should use a real QUIC/yamux stack. */
void handle_quic_data_pump(int quic_fd, int target_udp_fd, struct sockaddr_in *target_addr, cwist_yamux_session_t *session) {
    (void)session;
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

        if (fds[0].revents & POLLIN) {
            ssize_t n = read(quic_fd, buf, sizeof(buf));
            if (n > 0) {
                sendto(target_udp_fd, buf, n, 0, (struct sockaddr *)target_addr, sizeof(*target_addr));
            }
        }

        if (fds[1].revents & POLLIN) {
            ssize_t n = recvfrom(target_udp_fd, buf, sizeof(buf), 0, NULL, NULL);
            if (n > 0) {
                yamux_header_t hdr = {
                    .version = 0,
                    .type = YAMUX_TYPE_DATA,
                    .flags = 0,
                    .stream_id = 1,
                    .length = (uint32_t)n
                };
                if (write(quic_fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) break;
                if (write(quic_fd, buf, n) != n) break;
            }
        }
    }
}

void handle_quic_control(const uint8_t *payload, size_t len, struct sockaddr_in *client_addr) {
    (void)len;
    (void)client_addr;
    cJSON *root = cJSON_Parse((const char *)payload);
    if (root) {
        cJSON *token = cJSON_GetObjectItem(root, "access_token");
        if (token && token->valuestring) {
            LOG_INFO("QUIC: Access granted for token: %s", token->valuestring);
            /* A full implementation would validate the token, resolve the
             * target UDP endpoint, and start handle_quic_data_pump(...).
             * The required target addressing is not present in the current
             * control message schema, so the pump is left unstarted here. */
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
