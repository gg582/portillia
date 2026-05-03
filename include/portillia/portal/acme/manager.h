#ifndef PORTILLIA_PORTAL_ACME_MANAGER_H
#define PORTILLIA_PORTAL_ACME_MANAGER_H

#include "provider.h"
#include <cwist/sys/err/cwist_err.h>
#include <cwist/core/sstring/sstring.h>

typedef struct {
    char *base_domain;
    char *key_dir;
    char *dns_provider_type;
    int ens_gasless_enabled;
    char *ens_gasless_address;
    char *cloudflare_token;
    char *gcp_project_id;
    char *gcp_managed_zone;
    char *njalla_token;
    char *aws_access_key_id;
    char *aws_secret_access_key;
    char *aws_session_token;
    char *aws_region;
    char *aws_hosted_zone_id;
    char *aws_kms_key_arn;
} portillia_acme_config;

struct portillia_acme_manager {
    portillia_acme_config cfg;
    portillia_dns_provider *dns;
    // ACME Account details
    char *acme_account_key_path;
    char *acme_email;
    // Placeholder for lego client in C context
};


portillia_acme_manager* portillia_acme_manager_new(portillia_acme_config cfg);
void portillia_acme_manager_destroy(portillia_acme_manager *m);

int portillia_acme_manager_ensure_certificate(portillia_acme_manager *m, char **cert_file, char **key_file);
int portillia_acme_manager_sync_dns(portillia_acme_manager *m);
int portillia_acme_manager_sync_ens_gasless(portillia_acme_manager *m);

#endif // PORTILLIA_PORTAL_ACME_MANAGER_H
