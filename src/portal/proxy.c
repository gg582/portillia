#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

/**
 * @brief Bridge two sockets.
 */
void portillia_proxy_bridge(int client_fd, int target_fd) {
    struct pollfd fds[2];
    fds[0].fd = client_fd;
    fds[0].events = POLLIN;
    fds[1].fd = target_fd;
    fds[1].events = POLLIN;

    char buf[4096];
    while (1) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) break;
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(client_fd, buf, sizeof(buf));
            if (n <= 0) break;
            write(target_fd, buf, n);
        }
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(target_fd, buf, sizeof(buf));
            if (n <= 0) break;
            write(client_fd, buf, n);
        }
    }
    close(client_fd);
    close(target_fd);
}
