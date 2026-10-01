#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <portillia/portal/keyless/bindings.h>
#include <portillia/utils/log.h>

/* Mirror of bindings.go helloFixingConn: captures the first relay-observed
 * ClientHello on the browser->sdk direction and pins it (sha256) to the
 * binding minted at claim time. */
typedef struct {
    portillia_ch_accum acc;
    bool fixed;
    uint8_t binding[PORTILLIA_BINDING_SIZE];
} hello_capture;

typedef struct {
    int src;
    int dst;
    int64_t bps_limit;
    bool capture; /* set on the client->target direction when a binding is active */
    hello_capture cap;
} copy_args;

typedef struct {
    int client_fd;
    int target_fd;
    int64_t bps_limit;
    bool has_binding;
    uint8_t binding[PORTILLIA_BINDING_SIZE];
} bridge_args;

#define COPY_CHUNK (1 << 16)        /* 64 KiB per splice */
#define PIPE_BUF_SIZE (1 << 20)     /* 1 MiB kernel pipe buffer */

static atomic_int_fast64_t global_active_conns = 0;
static atomic_int_fast64_t global_total_bytes = 0;
static double current_bps = 0.0;

void *telemetry_sampler_thread(void *arg) {
    (void)arg;
    int64_t last_bytes = 0;
    while (1) {
        sleep(1);
        int64_t current_total = atomic_load(&global_total_bytes);
        current_bps = (double)(current_total - last_bytes) * 8.0;
        last_bytes = current_total;
    }
    return NULL;
}

void portillia_proxy_init_telemetry(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, telemetry_sampler_thread, NULL) == 0) {
        pthread_detach(tid);
    }
}

int64_t portillia_proxy_get_active_conns(void) {
    return atomic_load(&global_active_conns);
}

double portillia_proxy_get_current_bps(void) {
    return current_bps;
}

/* Feeds buf into the capture, fixing the binding once the first ClientHello
 * is complete. Mirrors helloFixingConn.Write: preview before write, fix on
 * completion, fail the write on capture error. */
static bool capture_on_write(hello_capture *cap, const uint8_t *buf, ssize_t n) {
    if (cap->fixed) return true;

    portillia_ch_accum preview = cap->acc;
    uint8_t *cloned_pending = NULL, *cloned_hello = NULL;
    if (cap->acc.pending_len) {
        cloned_pending = malloc(cap->acc.pending_len);
        memcpy(cloned_pending, cap->acc.pending, cap->acc.pending_len);
    }
    if (cap->acc.hello_len) {
        cloned_hello = malloc(cap->acc.hello_len);
        memcpy(cloned_hello, cap->acc.hello, cap->acc.hello_len);
    }
    preview.pending = cloned_pending;
    preview.hello = cloned_hello;

    uint8_t *hello = NULL;
    size_t hello_len = 0;
    bool complete = false;
    portillia_binding_status st = portillia_ch_accum_add(&preview, buf, (size_t)n,
                                                         &hello, &hello_len, &complete);
    if (st != PORTILLIA_BINDING_OK) {
        LOG_WARN("capture client hello for binding: %s", portillia_binding_strerror(st));
        free(cloned_pending);
        free(cloned_hello);
        return false;
    }
    if (complete) {
        st = portillia_bindings_fix_hello(portillia_bindings_shared(), cap->binding,
                                          hello, hello_len);
        free(hello);
        free(cloned_pending);
        free(cloned_hello);
        if (st != PORTILLIA_BINDING_OK) {
            LOG_WARN("fix binding client hello: %s", portillia_binding_strerror(st));
            return false;
        }
        cap->fixed = true;
        return true;
    }

    /* Preview still incomplete: write through, then advance the real state. */
    free(cloned_pending);
    free(cloned_hello);
    return true;
}

static void capture_after_write(hello_capture *cap, const uint8_t *buf, ssize_t n) {
    if (cap->fixed) return;
    uint8_t *hello = NULL;
    size_t hello_len = 0;
    bool complete = false;
    portillia_binding_status st = portillia_ch_accum_add(&cap->acc, buf, (size_t)n,
                                                         &hello, &hello_len, &complete);
    if (st == PORTILLIA_BINDING_OK && complete) {
        /* Cannot happen (preview would have caught it), but stay safe. */
        if (portillia_bindings_fix_hello(portillia_bindings_shared(), cap->binding,
                                         hello, hello_len) == PORTILLIA_BINDING_OK) {
            cap->fixed = true;
        }
    }
    free(hello);
}

/* Zero-copy splice src -> dst using a pipe. Falls back to read/write if the
 * kernel rejects splice on this fd pair. Throttling is enforced after each
 * chunk so the tight inner loop stays in the kernel. When a capture is
 * active, splice is skipped entirely so bytes pass through userspace. */
static void splice_copy(copy_args *args) {
    int src = args->src;
    int dst = args->dst;
    int64_t bytes_per_sec = args->bps_limit > 0 ? args->bps_limit / 8 : 0;
    bool capture = args->capture;

    int pipe_fds[2] = { -1, -1 };
    int splice_ok = 0;
    if (!capture && pipe2(pipe_fds, O_CLOEXEC) == 0) {
        (void)fcntl(pipe_fds[0], F_SETPIPE_SZ, PIPE_BUF_SIZE);
        splice_ok = 1;
        while (1) {
            ssize_t n = splice(src, NULL, pipe_fds[1], NULL, COPY_CHUNK,
                               SPLICE_F_MOVE | SPLICE_F_MORE);
            if (n < 0) {
                if (errno == EINTR) continue;
                /* EINVAL means these fds aren't splice-compatible; fall back. */
                if (errno == EINVAL) { splice_ok = 0; }
                break;
            }
            if (n == 0) break;

            ssize_t left = n;
            int writer_failed = 0;
            while (left > 0) {
                ssize_t w = splice(pipe_fds[0], NULL, dst, NULL, left,
                                   SPLICE_F_MOVE | SPLICE_F_MORE);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    writer_failed = 1;
                    break;
                }
                if (w == 0) { writer_failed = 1; break; }
                left -= w;
            }
            if (writer_failed) break;
            atomic_fetch_add(&global_total_bytes, n);

            if (bytes_per_sec > 0) {
                usleep((useconds_t)((double)n / bytes_per_sec * 1000000.0));
            }
        }
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }
    if (splice_ok) return;

    /* Fallback path - only reached if splice errored out or pipe2 failed,
     * or if a ClientHello capture is active (bytes must cross userspace). */
    char buf[COPY_CHUNK];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        if (capture && !capture_on_write(&args->cap, (const uint8_t *)buf, n)) return;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(dst, buf + off, n - off);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return;
            }
            off += w;
        }
        if (capture) capture_after_write(&args->cap, (const uint8_t *)buf, n);
        atomic_fetch_add(&global_total_bytes, n);
        if (bytes_per_sec > 0) {
            usleep((useconds_t)((double)n / bytes_per_sec * 1000000.0));
        }
    }
}

void *copy_thread(void *arg) {
    copy_args *args = (copy_args *)arg;
    atomic_fetch_add(&global_active_conns, 1);

    splice_copy(args);

    atomic_fetch_add(&global_active_conns, -1);
    if (args->capture) portillia_ch_accum_reset(&args->cap.acc);
    shutdown(args->dst, SHUT_WR);
    shutdown(args->src, SHUT_RD);
    free(args);
    return NULL;
}

void *bridge_thread_func(void *arg) {
    bridge_args *b_args = (bridge_args *)arg;
    int client_fd = b_args->client_fd;
    int target_fd = b_args->target_fd;
    int64_t bps_limit = b_args->bps_limit;
    bool has_binding = b_args->has_binding;
    uint8_t binding[PORTILLIA_BINDING_SIZE];
    if (has_binding) memcpy(binding, b_args->binding, PORTILLIA_BINDING_SIZE);
    free(b_args);

    int nodelay = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    setsockopt(target_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    pthread_t t1, t2;
    copy_args *args1 = malloc(sizeof(copy_args));
    args1->src = client_fd;
    args1->dst = target_fd;
    args1->bps_limit = bps_limit;
    args1->capture = has_binding;
    if (has_binding) {
        portillia_ch_accum_init(&args1->cap.acc);
        args1->cap.fixed = false;
        memcpy(args1->cap.binding, binding, PORTILLIA_BINDING_SIZE);
    }
    int started1 = pthread_create(&t1, NULL, copy_thread, args1) == 0;
    if (!started1) free(args1);

    copy_args *args2 = malloc(sizeof(copy_args));
    args2->src = target_fd;
    args2->dst = client_fd;
    args2->bps_limit = bps_limit;
    args2->capture = false;
    int started2 = pthread_create(&t2, NULL, copy_thread, args2) == 0;
    if (!started2) free(args2);

    if (started1) pthread_join(t1, NULL);
    if (started2) pthread_join(t2, NULL);

    close(client_fd);
    close(target_fd);
    return NULL;
}

void portillia_proxy_bridge_bound(int client_fd, int target_fd, int64_t bps_limit,
                                  const uint8_t binding[PORTILLIA_BINDING_SIZE]) {
    pthread_t t;
    bridge_args *args = malloc(sizeof(bridge_args));
    if (!args) {
        close(client_fd);
        close(target_fd);
        return;
    }
    args->client_fd = client_fd;
    args->target_fd = target_fd;
    args->bps_limit = bps_limit;
    args->has_binding = binding != NULL;
    if (binding) memcpy(args->binding, binding, PORTILLIA_BINDING_SIZE);
    if (pthread_create(&t, NULL, bridge_thread_func, args) != 0) {
        free(args);
        close(client_fd);
        close(target_fd);
    } else {
        pthread_detach(t);
    }
}

void portillia_proxy_bridge_ex(int client_fd, int target_fd, int64_t bps_limit) {
    portillia_proxy_bridge_bound(client_fd, target_fd, bps_limit, NULL);
}

void portillia_proxy_bridge(int client_fd, int target_fd) {
    portillia_proxy_bridge_ex(client_fd, target_fd, 0);
}

/* ------------------------------------------------------------------ */
/* SSL-aware bridge: one side is a raw TCP fd, the other is an OpenSSL
 * object (e.g. a cwist-terminated TLS reverse session).                */
/* ------------------------------------------------------------------ */

#include <openssl/ssl.h>

typedef struct {
    int client_fd;
    SSL *ssl;
    int64_t bps_limit;
    bool has_binding;
    uint8_t binding[PORTILLIA_BINDING_SIZE];
} ssl_bridge_args;

typedef struct {
    int client_fd;
    SSL *ssl;
    pthread_mutex_t *ssl_mu;
    int64_t bps_limit;
    bool capture;
    hello_capture cap;
} ssl_copy_args;

static void ssl_sleep_for_bytes(size_t n, int64_t bytes_per_sec) {
    if (bytes_per_sec > 0) {
        usleep((useconds_t)((double)n / bytes_per_sec * 1000000.0));
    }
}

static void *ssl_copy_fd_to_ssl(void *arg) {
    ssl_copy_args *a = (ssl_copy_args *)arg;
    int fd = a->client_fd;
    SSL *ssl = a->ssl;
    int64_t bytes_per_sec = a->bps_limit > 0 ? a->bps_limit / 8 : 0;
    bool capture = a->capture;
    hello_capture cap = a->cap;
    free(a);

    char buf[COPY_CHUNK];
    while (1) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        if (capture && !capture_on_write(&cap, (const uint8_t *)buf, n)) break;
        ssize_t off = 0;
        while (off < n) {
            /* No lock: this thread only writes while the peer thread only
             * reads; taking the shared mutex here would block behind a
             * blocking SSL_read and deadlock the splice. */
            int w = SSL_write(ssl, buf + off, (int)(n - off));
            if (w > 0) {
                off += w;
                continue;
            }
            int err = SSL_get_error(ssl, w);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) continue;
            goto done;
        }
        if (capture) capture_after_write(&cap, (const uint8_t *)buf, n);
        atomic_fetch_add(&global_total_bytes, n);
        ssl_sleep_for_bytes((size_t)n, bytes_per_sec);
    }
done:
    if (capture) portillia_ch_accum_reset(&cap.acc);
    shutdown(fd, SHUT_RD);
    return NULL;
}

static void *ssl_copy_ssl_to_fd(void *arg) {
    ssl_copy_args *a = (ssl_copy_args *)arg;
    int fd = a->client_fd;
    SSL *ssl = a->ssl;
    int64_t bytes_per_sec = a->bps_limit > 0 ? a->bps_limit / 8 : 0;
    free(a);

    char buf[COPY_CHUNK];
    while (1) {
        /* No lock: one thread only ever reads this SSL while another only
         * writes it; holding the mutex across a blocking SSL_read would
         * deadlock the writer. */
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n > 0) {
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write(fd, buf + off, n - off);
                if (w <= 0) {
                    if (w < 0 && errno == EINTR) continue;
                    goto done;
                }
                off += w;
            }
            atomic_fetch_add(&global_total_bytes, n);
            ssl_sleep_for_bytes((size_t)n, bytes_per_sec);
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        break;
    }
done:
    shutdown(fd, SHUT_WR);
    return NULL;
}

static void *ssl_bridge_thread_func(void *arg) {
    ssl_bridge_args *b = (ssl_bridge_args *)arg;
    int client_fd = b->client_fd;
    SSL *ssl = b->ssl;
    int64_t bps_limit = b->bps_limit;
    bool has_binding = b->has_binding;
    uint8_t binding[PORTILLIA_BINDING_SIZE];
    if (has_binding) memcpy(binding, b->binding, PORTILLIA_BINDING_SIZE);
    free(b);

    pthread_mutex_t ssl_mu = PTHREAD_MUTEX_INITIALIZER;

    int nodelay = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    ssl_copy_args *a1 = malloc(sizeof(ssl_copy_args));
    ssl_copy_args *a2 = malloc(sizeof(ssl_copy_args));
    if (!a1 || !a2) {
        free(a1);
        free(a2);
        pthread_mutex_destroy(&ssl_mu);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return NULL;
    }
    a1->client_fd = client_fd; a1->ssl = ssl; a1->ssl_mu = &ssl_mu; a1->bps_limit = bps_limit;
    a1->capture = has_binding;
    if (has_binding) {
        portillia_ch_accum_init(&a1->cap.acc);
        a1->cap.fixed = false;
        memcpy(a1->cap.binding, binding, PORTILLIA_BINDING_SIZE);
    }
    a2->client_fd = client_fd; a2->ssl = ssl; a2->ssl_mu = &ssl_mu; a2->bps_limit = bps_limit;
    a2->capture = false;

    pthread_t t1, t2;
    pthread_create(&t1, NULL, ssl_copy_fd_to_ssl, a1);
    pthread_create(&t2, NULL, ssl_copy_ssl_to_fd, a2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    pthread_mutex_lock(&ssl_mu);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    pthread_mutex_unlock(&ssl_mu);
    pthread_mutex_destroy(&ssl_mu);
    close(client_fd);
    return NULL;
}

void portillia_proxy_ssl_bridge_bound(int client_fd, SSL *target_ssl, int64_t bps_limit,
                                      const uint8_t binding[PORTILLIA_BINDING_SIZE]) {
    ssl_bridge_args *args = malloc(sizeof(ssl_bridge_args));
    if (!args) {
        SSL_shutdown(target_ssl);
        SSL_free(target_ssl);
        close(client_fd);
        return;
    }
    args->client_fd = client_fd;
    args->ssl = target_ssl;
    args->bps_limit = bps_limit;
    args->has_binding = binding != NULL;
    if (binding) memcpy(args->binding, binding, PORTILLIA_BINDING_SIZE);
    pthread_t t;
    if (pthread_create(&t, NULL, ssl_bridge_thread_func, args) != 0) {
        free(args);
        SSL_shutdown(target_ssl);
        SSL_free(target_ssl);
        close(client_fd);
    } else {
        pthread_detach(t);
    }
}

void portillia_proxy_ssl_bridge_ex(int client_fd, SSL *target_ssl, int64_t bps_limit) {
    portillia_proxy_ssl_bridge_bound(client_fd, target_ssl, bps_limit, NULL);
}
