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