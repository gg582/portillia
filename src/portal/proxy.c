#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>

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

#include <stdatomic.h>

static atomic_int_fast64_t global_active_conns = 0;
static atomic_int_fast64_t global_total_bytes = 0;
static double current_bps = 0.0;

void *telemetry_sampler_thread(void *arg) {
    int64_t last_bytes = 0;
    while (1) {
        sleep(1);
        int64_t current_total = atomic_load(&global_total_bytes);
        current_bps = (double)(current_total - last_bytes) * 8.0; // Bits per second
        last_bytes = current_total;
    }
    return NULL;
}

void portillia_proxy_init_telemetry() {
    pthread_t tid;
    if (pthread_create(&tid, NULL, telemetry_sampler_thread, NULL) == 0) {
        pthread_detach(tid);
    }
}

int64_t portillia_proxy_get_active_conns() {
    return atomic_load(&global_active_conns);
}

double portillia_proxy_get_current_bps() {
    return current_bps;
}

void *copy_thread(void *arg) {
    copy_args *args = (copy_args *)arg;
    char buf[32768];
    ssize_t n;
    
    atomic_fetch_add(&global_active_conns, 1);
    int64_t bytes_per_sec = args->bps_limit / 8;
    
    while ((n = read(args->src, buf, sizeof(buf))) > 0) {
        if (write(args->dst, buf, n) < 0) break;
        
        atomic_fetch_add(&global_total_bytes, n);

        if (bytes_per_sec > 0) {
            double sleep_sec = (double)n / bytes_per_sec;
            usleep((useconds_t)(sleep_sec * 1000000));
        }
    }
    atomic_fetch_add(&global_active_conns, -1);
    shutdown(args->dst, SHUT_RDWR);
    shutdown(args->src, SHUT_RDWR);
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
    if (pthread_create(&t1, NULL, copy_thread, args1) != 0) {
        free(args1);
        close(client_fd);
        close(target_fd);
        return NULL;
    }
    
    copy_args *args2 = malloc(sizeof(copy_args));
    args2->src = target_fd;
    args2->dst = client_fd;
    args2->bps_limit = bps_limit;
    if (pthread_create(&t2, NULL, copy_thread, args2) != 0) {
        free(args2);
        shutdown(client_fd, SHUT_RDWR);
        shutdown(target_fd, SHUT_RDWR);
    }
    
    pthread_join(t1, NULL);
    if (t2) pthread_join(t2, NULL);

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