#include <portillia/portal/acme/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <portillia/utils/log.h>

typedef struct {
    portillia_dns_provider base;
    char *project_id;
    char *managed_zone;
} gcloud_provider;

static const char* gcloud_name(portillia_dns_provider *p) {
    return "gcloud";
}

static int gcloud_ensure_a_records(portillia_dns_provider *p, const char *base_domain, const char *public_ipv4) {
    LOG_WARN("Google Cloud DNS ensure_a_records not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int gcloud_ensure_a_record(portillia_dns_provider *p, const char *name, const char *public_ipv4) {
    LOG_WARN("Google Cloud DNS ensure_a_record not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int gcloud_delete_a_record(portillia_dns_provider *p, const char *name) {
    LOG_WARN("Google Cloud DNS delete_a_record not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int gcloud_ensure_txt_record(portillia_dns_provider *p, const char *name, const char *value) {
    LOG_WARN("Google Cloud DNS ensure_txt_record not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int gcloud_delete_txt_records(portillia_dns_provider *p, const char *name, const char *match_prefix) {
    LOG_WARN("Google Cloud DNS delete_txt_records not yet implemented in C version.");
    return CWIST_FAILURE;
}

static int gcloud_ensure_dnssec(portillia_dns_provider *p, const char *base_domain, cwist_sstring *state, cwist_sstring *ds_record, cwist_sstring *message) {
    LOG_WARN("Google Cloud DNS ensure_dnssec not yet implemented in C version.");
    return CWIST_FAILURE;
}

static void gcloud_destroy(portillia_dns_provider *p) {
    gcloud_provider *gp = (gcloud_provider *)p;
    free(gp->project_id);
    free(gp->managed_zone);
    free(gp);
}

portillia_dns_provider* portillia_gcloud_new(const char *project_id, const char *managed_zone) {
    gcloud_provider *gp = calloc(1, sizeof(gcloud_provider));
    gp->base.name = gcloud_name;
    gp->base.ensure_a_records = gcloud_ensure_a_records;
    gp->base.ensure_a_record = gcloud_ensure_a_record;
    gp->base.delete_a_record = gcloud_delete_a_record;
    gp->base.ensure_txt_record = gcloud_ensure_txt_record;
    gp->base.delete_txt_records = gcloud_delete_txt_records;
    gp->base.ensure_dnssec = gcloud_ensure_dnssec;
    gp->base.destroy = gcloud_destroy;
    
    gp->project_id = project_id ? strdup(project_id) : NULL;
    gp->managed_zone = managed_zone ? strdup(managed_zone) : NULL;
    
    return &gp->base;
}
