#ifndef PORTILLIA_PORTAL_TLS_PROXY_H
#define PORTILLIA_PORTAL_TLS_PROXY_H

int portillia_tls_proxy_init(const char *cert_path, const char *key_path);
int portillia_tls_proxy_apply_ech(const char *ech_pem_path);
void portillia_tls_proxy_bridge(int client_fd, int target_fd);

#endif
