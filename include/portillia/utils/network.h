#ifndef PORTILLIA_UTILS_NETWORK_H
#define PORTILLIA_UTILS_NETWORK_H

#include <stdint.h>

int portillia_network_listen_tcp(const char *addr, uint16_t port);

#endif // PORTILLIA_UTILS_NETWORK_H
