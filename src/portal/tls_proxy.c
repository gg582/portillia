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
static pthread_mutex_t ssl_mu = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    SSL *ssl;
    int fd;
} tls_copy_args;

static void *tls_client_to_target(void *arg) {
    tls_copy_args *args = (tls_copy_args *)arg;
    char buf[32768];
    int n;
    while (1) {
        pthread_mutex_lock(&ssl_mu);
        n = SSL_read(args->ssl, buf, sizeof(buf));
        pthread_mutex_unlock(&ssl_mu);
        if (n <= 0) break;
        if (write(args->fd, buf, n) < 0) break;
    }
    shutdown(args->fd, SHUT_RDWR);
    int ssl_fd = SSL_get_fd(args->ssl);
    if (ssl_fd >= 0) shutdown(ssl_fd, SHUT_RDWR);
    free(args);
    return NULL;
}

static void *tls_target_to_client(void *arg) {
    tls_copy_args *args = (tls_copy_args *)arg;
    char buf[32768];
    int n;
    while ((n = read(args->fd, buf, sizeof(buf))) > 0) {
        pthread_mutex_lock(&ssl_mu);
        int w = SSL_write(args->ssl, buf, n);
        pthread_mutex_unlock(&ssl_mu);
        if (w <= 0) break;
    }
    shutdown(args->fd, SHUT_RDWR);
    int ssl_fd = SSL_get_fd(args->ssl);
    if (ssl_fd >= 0) shutdown(ssl_fd, SHUT_RDWR);
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

typedef struct {
    int client_fd;
    int target_fd;
} tls_bridge_args;

static void *tls_bridge_thread(void *arg) {
    tls_bridge_args *b_args = (tls_bridge_args *)arg;
    int client_fd = b_args->client_fd;
    int target_fd = b_args->target_fd;
    free(b_args);

    SSL *ssl = SSL_new(tls_ctx);
    if (!ssl) {
        close(client_fd);
        close(target_fd);
        return NULL;
    }
    SSL_set_fd(ssl, client_fd);
    
    if (SSL_accept(ssl) <= 0) {
        int ssl_err = SSL_get_error(ssl, -1);
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        LOG_ERROR("SSL_accept failed: ssl_err=%d, err=%s", ssl_err, err_buf);
        SSL_free(ssl);
        close(client_fd);
        close(target_fd);
        return NULL;
    }
    
    pthread_t t1, t2;
    tls_copy_args *args1 = malloc(sizeof(tls_copy_args));
    args1->ssl = ssl;
    args1->fd = target_fd;
    if (pthread_create(&t1, NULL, tls_client_to_target, args1) != 0) {
        free(args1);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        close(target_fd);
        return NULL;
    }
    
    tls_copy_args *args2 = malloc(sizeof(tls_copy_args));
    args2->ssl = ssl;
    args2->fd = target_fd;
    if (pthread_create(&t2, NULL, tls_target_to_client, args2) != 0) {
        free(args2);
        shutdown(client_fd, SHUT_RDWR);
        shutdown(target_fd, SHUT_RDWR);
    }
    
    pthread_join(t1, NULL);
    if (t2) pthread_join(t2, NULL);
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(target_fd);
    return NULL;
}

void portillia_tls_proxy_bridge(int client_fd, int target_fd) {
    if (!tls_ctx) {
        close(client_fd);
        close(target_fd);
        return;
    }

    pthread_t tid;
    tls_bridge_args *args = malloc(sizeof(tls_bridge_args));
    args->client_fd = client_fd;
    args->target_fd = target_fd;
    if (pthread_create(&tid, NULL, tls_bridge_thread, args) != 0) {
        free(args);
        close(client_fd);
        close(target_fd);
    } else {
        pthread_detach(tid);
    }
}
