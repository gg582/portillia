#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>

typedef struct {
    int src;
    int dst;
} copy_args;

void *copy_thread(void *arg) {
    copy_args *args = (copy_args *)arg;
    char buf[32768];
    ssize_t n;
    while ((n = read(args->src, buf, sizeof(buf))) > 0) {
        if (write(args->dst, buf, n) < 0) break;
    }
    // Shutdown the write side of the destination
    shutdown(args->dst, SHUT_WR);
    free(args);
    return NULL;
}

/**
 * @brief Bridge two sockets.
 */
void portillia_proxy_bridge(int client_fd, int target_fd) {
    pthread_t t1, t2;
    copy_args *args1 = malloc(sizeof(copy_args));
    args1->src = client_fd;
    args1->dst = target_fd;
    pthread_create(&t1, NULL, copy_thread, args1);
    
    copy_args *args2 = malloc(sizeof(copy_args));
    args2->src = target_fd;
    args2->dst = client_fd;
    pthread_create(&t2, NULL, copy_thread, args2);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(client_fd);
    close(target_fd);
}
