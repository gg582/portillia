#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <portillia/utils/log.h>

static SSL_CTX *tls_ctx = NULL;

typedef struct {
    SSL *ssl;
    int fd;
} tls_copy_args;

static void *tls_client_to_target(void *arg) {
    tls_copy_args *args = (tls_copy_args *)arg;
    char buf[32768];
    int n;
    while ((n = SSL_read(args->ssl, buf, sizeof(buf))) > 0) {
        if (write(args->fd, buf, n) < 0) break;
    }
    shutdown(args->fd, SHUT_WR);
    free(args);
    return NULL;
}

static void *tls_target_to_client(void *arg) {
    tls_copy_args *args = (tls_copy_args *)arg;
    char buf[32768];
    int n;
    while ((n = read(args->fd, buf, sizeof(buf))) > 0) {
        if (SSL_write(args->ssl, buf, n) <= 0) break;
    }
    free(args);
    return NULL;
}

int portillia_tls_proxy_init(const char *cert_path, const char *key_path) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    tls_ctx = SSL_CTX_new(TLS_server_method());
    if (!tls_ctx) return -1;
    
    SSL_CTX_set_mode(tls_ctx, SSL_MODE_AUTO_RETRY);
    
    if (SSL_CTX_use_certificate_chain_file(tls_ctx, cert_path) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(tls_ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (!SSL_CTX_check_private_key(tls_ctx)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

void portillia_tls_proxy_bridge(int client_fd, int target_fd) {
    if (!tls_ctx) {
        close(client_fd);
        close(target_fd);
        return;
    }
    
    SSL *ssl = SSL_new(tls_ctx);
    if (!ssl) {
        close(client_fd);
        close(target_fd);
        return;
    }
    SSL_set_fd(ssl, client_fd);
    
    if (SSL_accept(ssl) <= 0) {
        SSL_free(ssl);
        close(client_fd);
        close(target_fd);
        return;
    }
    
    pthread_t t1, t2;
    tls_copy_args *args1 = malloc(sizeof(tls_copy_args));
    args1->ssl = ssl;
    args1->fd = target_fd;
    pthread_create(&t1, NULL, tls_client_to_target, args1);
    
    tls_copy_args *args2 = malloc(sizeof(tls_copy_args));
    args2->ssl = ssl;
    args2->fd = target_fd;
    pthread_create(&t2, NULL, tls_target_to_client, args2);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(target_fd);
}
