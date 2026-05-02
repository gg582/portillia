#include <openssl/ssl.h>
#include <openssl/err.h>

/**
 * @brief Function portillia_tls_setup
 * @return void result
 */
void portillia_tls_setup(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}
