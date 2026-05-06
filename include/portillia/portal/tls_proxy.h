#ifndef PORTILLIA_PORTAL_TLS_PROXY_H
#define PORTILLIA_PORTAL_TLS_PROXY_H

int portillia_tls_proxy_init(const char *cert_path, const char *key_path);
void portillia_tls_proxy_bridge(int client_fd, int target_fd);

#endif
