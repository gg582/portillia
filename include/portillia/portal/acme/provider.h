#ifndef PORTILLIA_PORTAL_ACME_PROVIDER_H
#define PORTILLIA_PORTAL_ACME_PROVIDER_H

#include <cwist/sys/err/cwist_err.h>
#include <cwist/core/sstring/sstring.h>

typedef struct portillia_dns_provider portillia_dns_provider;

struct portillia_dns_provider {
    const char* (*name)(portillia_dns_provider *p);
    int (*ensure_a_records)(portillia_dns_provider *p, const char *base_domain, const char *public_ipv4);
    int (*ensure_a_record)(portillia_dns_provider *p, const char *name, const char *public_ipv4);
    int (*delete_a_record)(portillia_dns_provider *p, const char *name);
    int (*ensure_txt_record)(portillia_dns_provider *p, const char *name, const char *value);
    int (*delete_txt_records)(portillia_dns_provider *p, const char *name, const char *match_prefix);
    int (*ensure_dnssec)(portillia_dns_provider *p, const char *base_domain, cwist_sstring *state, cwist_sstring *ds_record, cwist_sstring *message);
    void (*destroy)(portillia_dns_provider *p);
};

portillia_dns_provider* portillia_cloudflare_new(const char *token);
portillia_dns_provider* portillia_route53_new(const char *access_key_id, const char *secret_access_key, const char *session_token, const char *region, const char *hosted_zone_id, const char *kms_key_arn);
portillia_dns_provider* portillia_gcloud_new(const char *project_id, const char *managed_zone);

#endif // PORTILLIA_PORTAL_ACME_PROVIDER_H
