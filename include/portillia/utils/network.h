/**
 * @file network.h
 * @brief Network utility functions for Portillia.
 */

#ifndef PORTILLIA_UTILS_NETWORK_H
#define PORTILLIA_UTILS_NETWORK_H

#include <stdbool.h>
#include <stdint.h>
#include <curl/curl.h>
#include <openssl/ssl.h>

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

/**
 * @brief Apply the SDK's TLS verification policy to a curl handle.
 */
void portillia_network_configure_curl_tls(CURL *curl, bool insecure_skip_verify);

/**
 * @brief Apply the SDK's TLS verification policy to an OpenSSL client context.
 * @return 0 on success, -1 on error.
 */
int portillia_network_configure_ssl_client_ctx(SSL_CTX *ctx, bool insecure_skip_verify);

#endif // PORTILLIA_UTILS_NETWORK_H
