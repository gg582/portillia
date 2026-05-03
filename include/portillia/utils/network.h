/**
 * @file network.h
 * @brief Network utility functions for Portillia.
 */

#ifndef PORTILLIA_UTILS_NETWORK_H
#define PORTILLIA_UTILS_NETWORK_H

#include <stdint.h>

/**
 * @brief Listens for incoming TCP connections.
 * @param addr Address string (e.g. "0.0.0.0").
 * @param port Port number.
 * @return Listening socket file descriptor.
 */
int portillia_network_listen_tcp(const char *addr, uint16_t port);

/**
 * @brief Checks if an IP is within a CIDR range.
 * @param ip IP address string.
 * @param cidr CIDR range string (e.g. "192.168.1.0/24").
 * @return 1 if inside, 0 if outside.
 */
int portillia_network_ip_in_cidr(const char *ip, const char *cidr);

/**
 * @brief Checks if a hostname matches a pattern (wildcard support).
 * @param pattern Pattern with optional leading wildcard (e.g., "*.example.com" or "host.example.com").
 * @param hostname Hostname to check.
 * @return 1 if matches, 0 if not.
 */
int hostname_matches(const char *pattern, const char *hostname);

#endif // PORTILLIA_UTILS_NETWORK_H