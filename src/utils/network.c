#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Check if an IP address is within a CIDR range.
 */
int portillia_network_ip_in_cidr(const char *ip, const char *cidr) {
    char cidr_copy[64];
    strncpy(cidr_copy, cidr, sizeof(cidr_copy));
    
    char *slash = strchr(cidr_copy, '/');
    if (!slash) return strcmp(ip, cidr) == 0;
    
    *slash = '\0';
    int mask_bits = atoi(slash + 1);
    
    struct in_addr ip_addr, cidr_addr;
    inet_pton(AF_INET, ip, &ip_addr);
    inet_pton(AF_INET, cidr_copy, &cidr_addr);
    
    uint32_t ip_h = ntohl(ip_addr.s_addr);
    uint32_t cidr_h = ntohl(cidr_addr.s_addr);
    
    uint32_t mask = (mask_bits == 0) ? 0 : (~0U << (32 - mask_bits));
    
    return (ip_h & mask) == (cidr_h & mask);
}

int portillia_network_listen_tcp(const char *addr, uint16_t port) {
    // Already handled in main.c and cwist
    return -1;
}

/**
 * @brief Checks if a hostname matches a pattern (wildcard support).
 * @param pattern Pattern with optional leading wildcard (e.g., "*.example.com" or "host.example.com").
 * @param hostname Hostname to check.
 * @return 1 if matches, 0 if not.
 */
int hostname_matches(const char *pattern, const char *hostname) {
    if (!pattern || !hostname) return 0;

    if (pattern[0] == '*') {
        // Wildcard match: *.example.com should match host.example.com
        if (strlen(hostname) < strlen(pattern)) return 0;
        return strcmp(hostname + strlen(hostname) - (strlen(pattern) - 1), pattern + 1) == 0;
    } else {
        // Exact match
        return strcmp(pattern, hostname) == 0;
    }
}