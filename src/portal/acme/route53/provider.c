#include <portillia/portal/acme/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <portillia/utils/log.h>

typedef struct {
    portillia_dns_provider base;
    char *access_key_id;
    char *secret_access_key;
    char *session_token;
    char *region;
    char *hosted_zone_id;
    char *kms_key_arn;
} route53_provider;

static const char* route53_name(portillia_dns_provider *p) {
    return "route53";
}

static int route53_ensure_a_records(portillia_dns_provider *p, const char *base_domain, const char *public_ipv4) {
    LOG_WARN("Route53 ensure_a_records not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int route53_ensure_a_record(portillia_dns_provider *p, const char *name, const char *public_ipv4) {
    LOG_WARN("Route53 ensure_a_record not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int route53_delete_a_record(portillia_dns_provider *p, const char *name) {
    LOG_WARN("Route53 delete_a_record not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int route53_ensure_txt_record(portillia_dns_provider *p, const char *name, const char *value) {
    LOG_WARN("Route53 ensure_txt_record not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int route53_delete_txt_records(portillia_dns_provider *p, const char *name, const char *match_prefix) {
    LOG_WARN("Route53 delete_txt_records not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int route53_ensure_dnssec(portillia_dns_provider *p, const char *base_domain, cwist_sstring *state, cwist_sstring *ds_record, cwist_sstring *message) {
    LOG_WARN("Route53 ensure_dnssec not yet implemented in C version.");
    return CWIST_FAILURE;
}

static void route53_destroy(portillia_dns_provider *p) {
    route53_provider *rp = (route53_provider *)p;
    free(rp->access_key_id);
    free(rp->secret_access_key);
    free(rp->session_token);
    free(rp->region);
    free(rp->hosted_zone_id);
    free(rp->kms_key_arn);
    free(rp);
}

portillia_dns_provider* portillia_route53_new(const char *access_key_id, const char *secret_access_key, const char *session_token, const char *region, const char *hosted_zone_id, const char *kms_key_arn) {
    route53_provider *rp = calloc(1, sizeof(route53_provider));
    rp->base.name = route53_name;
    rp->base.ensure_a_records = route53_ensure_a_records;
    rp->base.ensure_a_record = route53_ensure_a_record;
    rp->base.delete_a_record = route53_delete_a_record;
    rp->base.ensure_txt_record = route53_ensure_txt_record;
    rp->base.delete_txt_records = route53_delete_txt_records;
    rp->base.ensure_dnssec = route53_ensure_dnssec;
    rp->base.destroy = route53_destroy;
    
    rp->access_key_id = access_key_id ? strdup(access_key_id) : NULL;
    rp->secret_access_key = secret_access_key ? strdup(secret_access_key) : NULL;
    rp->session_token = session_token ? strdup(session_token) : NULL;
    rp->region = region ? strdup(region) : NULL;
    rp->hosted_zone_id = hosted_zone_id ? strdup(hosted_zone_id) : NULL;
    rp->kms_key_arn = kms_key_arn ? strdup(kms_key_arn) : NULL;
    
    return &rp->base;
}
