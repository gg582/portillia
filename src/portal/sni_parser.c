/** @file sni_parser.c
 * @brief SNI hostname parsing using MSG_PEEK without terminating TLS.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <portillia/utils/log.h>

#define MAX_CLIENT_HELLO 4096

// Returns dynamically allocated string or NULL
char *get_sni_hostname(int client_fd) {
    char buf[MAX_CLIENT_HELLO];
    
    // Wait for data (like defaultClientHelloWait in Go)
    struct pollfd pfd = { .fd = client_fd, .events = POLLIN };
    if (poll(&pfd, 1, 2000) <= 0) return NULL;

    ssize_t n = recv(client_fd, buf, sizeof(buf), MSG_PEEK);
    if (n < 43) return NULL; // Too small for ClientHello

    // Check TLS Handshake record (0x16)
    if (buf[0] != 0x16) return NULL;
    
    // Check ClientHello message type (0x01)
    if (buf[5] != 0x01) return NULL;
    
    // Parse length and skip headers
    int pos = 43; // skip fixed length headers
    
    // Skip Session ID
    if (pos >= n) return NULL;
    int session_id_len = buf[pos];
    pos += 1 + session_id_len;
    
    // Skip Cipher Suites
    if (pos + 2 > n) return NULL;
    int cipher_suites_len = (buf[pos] << 8) | buf[pos + 1];
    pos += 2 + cipher_suites_len;
    
    // Skip Compression Methods
    if (pos + 1 > n) return NULL;
    int comp_methods_len = buf[pos];
    pos += 1 + comp_methods_len;
    
    // Parse Extensions
    if (pos + 2 > n) return NULL;
    int ext_len = (buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    
    int end = pos + ext_len;
    if (end > n) end = n;
    
    while (pos + 4 <= end) {
        int ext_type = (buf[pos] << 8) | buf[pos + 1];
        int ext_len = (buf[pos + 2] << 8) | buf[pos + 3];
        pos += 4;
        
        if (ext_type == 0x0000) { // Server Name Indication
            if (pos + 5 <= end) { // 2 byte list len, 1 byte type, 2 byte name len
                int name_len = (buf[pos + 3] << 8) | buf[pos + 4];
                if (pos + 5 + name_len <= end) {
                    char *hostname = malloc(name_len + 1);
                    memcpy(hostname, buf + pos + 5, name_len);
                    hostname[name_len] = '\0';
                    return hostname;
                }
            }
        }
        pos += ext_len;
    }
    
    return NULL;
}
