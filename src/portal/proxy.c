#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

typedef struct {
    int src;
    int dst;
    int64_t bps_limit;
} copy_args;

typedef struct {
    int client_fd;
    int target_fd;
    int64_t bps_limit;
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

/* Zero-copy splice src -> dst using a pipe. Falls back to read/write if the
 * kernel rejects splice on this fd pair. Throttling is enforced after each
 * chunk so the tight inner loop stays in the kernel. */
static void splice_copy(int src, int dst, int64_t bps_limit) {
    int64_t bytes_per_sec = bps_limit > 0 ? bps_limit / 8 : 0;

    int pipe_fds[2] = { -1, -1 };
    int splice_ok = 0;
    if (pipe2(pipe_fds, O_CLOEXEC) == 0) {
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

    /* Fallback path - only reached if splice errored out or pipe2 failed. */
    char buf[COPY_CHUNK];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(dst, buf + off, n - off);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return;
            }
            off += w;
        }
        atomic_fetch_add(&global_total_bytes, n);
        if (bytes_per_sec > 0) {
            usleep((useconds_t)((double)n / bytes_per_sec * 1000000.0));
        }
    }
}

void *copy_thread(void *arg) {
    copy_args *args = (copy_args *)arg;
    atomic_fetch_add(&global_active_conns, 1);

    splice_copy(args->src, args->dst, args->bps_limit);

    atomic_fetch_add(&global_active_conns, -1);
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
    free(b_args);

    int nodelay = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    setsockopt(target_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    pthread_t t1, t2;
    copy_args *args1 = malloc(sizeof(copy_args));
    args1->src = client_fd;
    args1->dst = target_fd;
    args1->bps_limit = bps_limit;
    int started1 = pthread_create(&t1, NULL, copy_thread, args1) == 0;
    if (!started1) free(args1);

    copy_args *args2 = malloc(sizeof(copy_args));
    args2->src = target_fd;
    args2->dst = client_fd;
    args2->bps_limit = bps_limit;
    int started2 = pthread_create(&t2, NULL, copy_thread, args2) == 0;
    if (!started2) free(args2);

    if (started1) pthread_join(t1, NULL);
    if (started2) pthread_join(t2, NULL);

    close(client_fd);
    close(target_fd);
    return NULL;
}

void portillia_proxy_bridge_ex(int client_fd, int target_fd, int64_t bps_limit) {
    pthread_t t;
    bridge_args *args = malloc(sizeof(bridge_args));
    args->client_fd = client_fd;
    args->target_fd = target_fd;
    args->bps_limit = bps_limit;
    if (pthread_create(&t, NULL, bridge_thread_func, args) != 0) {
        free(args);
        close(client_fd);
        close(target_fd);
    } else {
        pthread_detach(t);
    }
}

void portillia_proxy_bridge(int client_fd, int target_fd) {
    portillia_proxy_bridge_ex(client_fd, target_fd, 0);
}
