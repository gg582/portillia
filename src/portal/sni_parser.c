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
#define CLIENT_HELLO_WAIT_MS 2000L

static long monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static ssize_t peek_full_before(int fd, unsigned char *buf, size_t want, long deadline_ms) {
    while (1) {
        int available = 0;
        if (ioctl(fd, FIONREAD, &available) == 0 && available >= (int)want) {
            ssize_t n;
            do {
                n = recv(fd, buf, want, MSG_PEEK);
            } while (n < 0 && errno == EINTR);
            return n;
        }
        long remaining_ms = deadline_ms - monotonic_ms();
        if (remaining_ms <= 0) {
            ssize_t n;
            do {
                n = recv(fd, buf, want, MSG_PEEK);
            } while (n < 0 && errno == EINTR);
            return n;
        }

        if (available > 0) {
            long sleep_us = remaining_ms > 10 ? 10000L : remaining_ms * 1000L;
            usleep((useconds_t)sleep_us);
            continue;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int rc;
        do {
            rc = poll(&pfd, 1, (int)remaining_ms);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0) {
            return -1;
        }
    }
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
    if (compression_len < 1 || pos + compression_len > msg_len) {
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

// Returns dynamically allocated, Go-normalized SNI hostname or NULL.
char *get_sni_hostname(int client_fd) {
    unsigned char header[TLS_RECORD_HEADER_LEN];
    long deadline_ms = monotonic_ms() + CLIENT_HELLO_WAIT_MS;

    ssize_t n = peek_full_before(client_fd, header, sizeof(header), deadline_ms);
    if (n != TLS_RECORD_HEADER_LEN) {
        LOG_INFO("SNI Parser: Could not read TLS record header (%ld bytes)", n);
        return NULL;
    }
    if (header[0] != TLS_CONTENT_TYPE_HANDSHAKE) {
        LOG_INFO("SNI Parser: Not a TLS handshake record (0x%02x)", header[0]);
        return NULL;
    }

    int record_len = (header[3] << 8) | header[4];
    if (record_len <= 0 || record_len > MAX_TLS_RECORD_BODY) {
        LOG_INFO("SNI Parser: Invalid ClientHello record length (%d)", record_len);
        return NULL;
    }

    size_t total_len = TLS_RECORD_HEADER_LEN + (size_t)record_len;
    unsigned char *record = malloc(total_len);
    if (!record) {
        return NULL;
    }

    n = peek_full_before(client_fd, record, total_len, deadline_ms);
    if (n != (ssize_t)total_len) {
        LOG_INFO("SNI Parser: Incomplete ClientHello record (%ld/%zu bytes)", n, total_len);
        free(record);
        return NULL;
    }

    char *hostname = parse_client_hello_record(record + TLS_RECORD_HEADER_LEN, record_len);
    free(record);

    if (!hostname) {
        LOG_INFO("SNI Parser: SNI extension not found or ClientHello invalid");
    }
    return hostname;
}
