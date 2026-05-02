/** @file sni_parser.c
 * @brief SNI hostname parsing using OpenSSL.
 */
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

const char *get_sni_hostname(int client_fd) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    
    // Perform minimal TLS handshake to read ClientHello
    if (SSL_accept(ssl) <= 0) {
        // Handle error
    }
    
    const char *hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return hostname;
}
