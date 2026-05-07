/** @file sni_parser.c
 * @brief SNI hostname parsing using MSG_PEEK without terminating TLS.
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <portillia/utils/log.h>

#define TLS_RECORD_HEADER_LEN 5
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_CONTENT_TYPE_HANDSHAKE 22
#define EXT_SERVER_NAME 0
#define MAX_TLS_RECORD_BODY 65535
#define MAX_CLIENT_HELLO_LEN (1 << 20)
#define CLIENT_HELLO_WAIT_MS 2000L

static long monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static char *normalize_server_name(const unsigned char *name, int name_len) {
    const unsigned char *start = name;
    const unsigned char *end = name + name_len;

    while (start < end && isspace(*start)) {
        start++;
    }
    while (end > start && isspace(*(end - 1))) {
        end--;
    }
    while (end > start && *(end - 1) == '.') {
        end--;
    }

    size_t out_len = (size_t)(end - start);
    if (out_len == 0) {
        return NULL;
    }

    char *out = malloc(out_len + 1);
    if (!out) {
        return NULL;
    }
    for (size_t i = 0; i < out_len; i++) {
        out[i] = (char)tolower(start[i]);
    }
    out[out_len] = '\0';
    return out;
}

static char *parse_server_name_extension(const unsigned char *ext, int ext_len) {
    if (ext_len < 2) {
        return NULL;
    }
    int list_len = (ext[0] << 8) | ext[1];
    if (list_len == 0 || 2 + list_len > ext_len) {
        return NULL;
    }

    int pos = 2;
    int end = 2 + list_len;
    while (pos + 3 <= end) {
        int name_type = ext[pos++];
        int name_len = (ext[pos] << 8) | ext[pos + 1];
        pos += 2;
        if (pos + name_len > end) {
            return NULL;
        }
        if (name_type == 0) {
            return normalize_server_name(ext + pos, name_len);
        }
        pos += name_len;
    }

    return NULL;
}

static char *parse_client_hello_record(const unsigned char *record_body, int record_len) {
    if (record_len < 4 || record_body[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        return NULL;
    }

    int msg_len = (record_body[1] << 16) | (record_body[2] << 8) | record_body[3];
    if (msg_len <= 0 || 4 + msg_len > record_len) {
        return NULL;
    }

    const unsigned char *msg = record_body + 4;
    if (msg_len < 34) {
        return NULL;
    }

    int pos = 34;
    if (pos >= msg_len) {
        return NULL;
    }

    int session_len = msg[pos++];
    if (pos + session_len > msg_len) {
        return NULL;
    }
    pos += session_len;

    if (pos + 2 > msg_len) {
        return NULL;
    }
    int cipher_len = (msg[pos] << 8) | msg[pos + 1];
    pos += 2;
    if (cipher_len < 2 || pos + cipher_len > msg_len) {
        return NULL;
    }
    pos += cipher_len;

    if (pos >= msg_len) {
        return NULL;
    }
    int compression_len = msg[pos++];
    if (compression_len < 0 || pos + compression_len > msg_len) {
        return NULL;
    }
    pos += compression_len;

    if (pos == msg_len) {
        return NULL;
    }
    if (pos + 2 > msg_len) {
        return NULL;
    }
    int extensions_len = (msg[pos] << 8) | msg[pos + 1];
    pos += 2;
    if (pos + extensions_len > msg_len) {
        return NULL;
    }

    int end = pos + extensions_len;
    while (pos + 4 <= end) {
        int ext_type = (msg[pos] << 8) | msg[pos + 1];
        pos += 2;
        int ext_len = (msg[pos] << 8) | msg[pos + 1];
        pos += 2;
        if (pos + ext_len > end) {
            return NULL;
        }

        if (ext_type == EXT_SERVER_NAME) {
            char *hostname = parse_server_name_extension(msg + pos, ext_len);
            if (hostname) {
                return hostname;
            }
        }
        pos += ext_len;
    }

    return NULL;
}

static char *parse_client_hello_stream(const unsigned char *stream, size_t stream_len, int *need_more) {
    size_t pos = 0;
    unsigned char *hello = NULL;
    size_t hello_have = 0;
    size_t hello_total = 0;
    int started = 0;
    *need_more = 0;

    while (pos + TLS_RECORD_HEADER_LEN <= stream_len) {
        int content_type = stream[pos];
        int record_len = (stream[pos + 3] << 8) | stream[pos + 4];
        size_t record_body = pos + TLS_RECORD_HEADER_LEN;
        size_t record_end = record_body + (size_t)record_len;
        if (record_len <= 0 || record_len > MAX_TLS_RECORD_BODY) {
            break;
        }
        if (record_end > stream_len) {
            *need_more = 1;
            break;
        }
        if (content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
            if (!started) {
                // TLS 1.3 middlebox compatibility: skip ChangeCipherSpec(20)
                if (content_type == 20) {
                    pos = record_end;
                    continue;
                }
                break;
            }
            pos = record_end;
            continue;
        }

        const unsigned char *payload = stream + record_body;
        size_t payload_len = (size_t)record_len;

        if (!started) {
            if (payload_len < 4) {
                *need_more = 1;
                break;
            }
            if (payload[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
                break;
            }
            int msg_len = (payload[1] << 16) | (payload[2] << 8) | payload[3];
            if (msg_len <= 0 || msg_len > MAX_CLIENT_HELLO_LEN) {
                break;
            }

            hello_total = (size_t)msg_len + 4;
            hello = malloc(hello_total);
            if (!hello) {
                return NULL;
            }
            size_t first = payload_len < hello_total ? payload_len : hello_total;
            memcpy(hello, payload, first);
            hello_have = first;
            started = 1;
            if (hello_have >= hello_total) {
                char *hostname = parse_client_hello_record(hello, (int)hello_total);
                free(hello);
                return hostname;
            }
            pos = record_end;
            continue;
        }

        size_t remaining = hello_total - hello_have;
        size_t to_copy = payload_len < remaining ? payload_len : remaining;
        memcpy(hello + hello_have, payload, to_copy);
        hello_have += to_copy;
        if (hello_have >= hello_total) {
            char *hostname = parse_client_hello_record(hello, (int)hello_total);
            free(hello);
            return hostname;
        }

        pos = record_end;
    }

    if (hello) {
        free(hello);
    }
    if (started) {
        *need_more = 1;
    } else if (stream_len < TLS_RECORD_HEADER_LEN) {
        *need_more = 1;
    }
    return NULL;
}

// Returns dynamically allocated, Go-normalized SNI hostname or NULL.
char *get_sni_hostname(int client_fd) {
    long deadline_ms = monotonic_ms() + CLIENT_HELLO_WAIT_MS;
    while (1) {
        int available = 0;
        if (ioctl(client_fd, FIONREAD, &available) != 0 || available <= 0) {
            long remaining_ms = deadline_ms - monotonic_ms();
            if (remaining_ms <= 0) {
                LOG_WARN("get_sni_hostname: timeout waiting for ClientHello data");
                return NULL;
            }
            struct pollfd pfd = { .fd = client_fd, .events = POLLIN };
            int rc;
            do {
                rc = poll(&pfd, 1, (int)remaining_ms);
            } while (rc < 0 && errno == EINTR);
            if (rc <= 0) {
                LOG_WARN("get_sni_hostname: poll failed rc=%d errno=%d", rc, errno);
                return NULL;
            }
            continue;
        }

        unsigned char *peeked = malloc((size_t)available);
        if (!peeked) {
            LOG_ERROR("get_sni_hostname: malloc failed for %d bytes", available);
            return NULL;
        }
        ssize_t n;
        do {
            n = recv(client_fd, peeked, (size_t)available, MSG_PEEK);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) {
            free(peeked);
            LOG_WARN("get_sni_hostname: recv failed n=%zd errno=%d", n, errno);
            return NULL;
        }
        int need_more = 0;
        char *hostname = parse_client_hello_stream(peeked, (size_t)n, &need_more);
        free(peeked);
        if (hostname) {
            LOG_INFO("get_sni_hostname: parsed hostname=%s", hostname);
            return hostname;
        }
        if (!need_more) {
            LOG_WARN("get_sni_hostname: parse_client_hello_stream failed, need_more=0");
            return NULL;
        }
        long remaining_ms = deadline_ms - monotonic_ms();
        if (remaining_ms <= 0) {
            LOG_WARN("get_sni_hostname: timeout after need_more");
            return NULL;
        }
        long sleep_us = remaining_ms > 10 ? 10000L : remaining_ms * 1000L;
        usleep((useconds_t)sleep_us);
    }
}
