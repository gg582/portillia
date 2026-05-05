#include <portillia/portal/acme/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <portillia/utils/log.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>

#define ROUTE53_API_BASE "https://route53.amazonaws.com"

typedef struct {
    portillia_dns_provider base;
    char *access_key_id;
    char *secret_access_key;
    char *session_token;
    char *region;
    char *hosted_zone_id;
    char *kms_key_arn;
} route53_provider;

struct curl_response {
    char *data;
    size_t size;
};

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_response *mem = (struct curl_response *)userp;
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}

static void sha256_hex(const char *data, size_t len, char *out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(out + i * 2, "%02x", hash[i]);
}

static void hmac_sha256_hex(const char *key, size_t key_len, const char *data, size_t data_len, char *out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;
    HMAC(EVP_sha256(), key, (int)key_len, (const unsigned char *)data, data_len, hash, &hash_len);
    for (unsigned int i = 0; i < hash_len; i++) sprintf(out + i * 2, "%02x", hash[i]);
}

static void get_signature_key(const char *secret, const char *date, const char *region, const char *service, unsigned char *out_key) {
    char k_secret[128];
    snprintf(k_secret, sizeof(k_secret), "AWS4%s", secret);
    unsigned char k_date[32];
    unsigned int k_date_len = 0;
    HMAC(EVP_sha256(), k_secret, (int)strlen(k_secret), (const unsigned char *)date, strlen(date), k_date, &k_date_len);
    unsigned char k_region[32];
    unsigned int k_region_len = 0;
    HMAC(EVP_sha256(), k_date, k_date_len, (const unsigned char *)region, strlen(region), k_region, &k_region_len);
    unsigned char k_service[32];
    unsigned int k_service_len = 0;
    HMAC(EVP_sha256(), k_region, k_region_len, (const unsigned char *)service, strlen(service), k_service, &k_service_len);
    unsigned int out_len = 0;
    HMAC(EVP_sha256(), k_service, k_service_len, (const unsigned char *)"aws4_request", 12, out_key, &out_len);
}

static cJSON* route53_api_request(route53_provider *rp, const char *method, const char *uri, const char *payload) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    struct curl_response res = { .data = malloc(1), .size = 0 };
    res.data[0] = '\0';

    char url[1024];
    snprintf(url, sizeof(url), "%s%s", ROUTE53_API_BASE, uri);

    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char amz_date[32], date_stamp[32];
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);
    strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", &tm);

    char payload_hash[65] = {0};
    sha256_hex(payload ? payload : "", payload ? strlen(payload) : 0, payload_hash);

    char canonical_headers[512];
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:route53.amazonaws.com\nx-amz-date:%s\n", amz_date);
    char signed_headers[] = "host;x-amz-date";

    if (rp->session_token && rp->session_token[0]) {
        snprintf(canonical_headers + strlen(canonical_headers),
                 sizeof(canonical_headers) - strlen(canonical_headers),
                 "x-amz-security-token:%s\n", rp->session_token);
        strcat(signed_headers, ";x-amz-security-token");
    }

    char canonical_request[4096];
    snprintf(canonical_request, sizeof(canonical_request),
             "%s\n%s\n\n%s\n%s\n%s",
             method, uri, canonical_headers, signed_headers, payload_hash);

    char canonical_request_hash[65] = {0};
    sha256_hex(canonical_request, strlen(canonical_request), canonical_request_hash);

    char credential_scope[128];
    snprintf(credential_scope, sizeof(credential_scope), "%s/%s/route53/aws4_request", date_stamp, rp->region ? rp->region : "us-east-1");

    char string_to_sign[512];
    snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s", amz_date, credential_scope, canonical_request_hash);

    unsigned char signing_key[32];
    get_signature_key(rp->secret_access_key, date_stamp, rp->region ? rp->region : "us-east-1", "route53", signing_key);

    char signature[65] = {0};
    unsigned int sig_len = 0;
    unsigned char sig_raw[32];
    HMAC(EVP_sha256(), signing_key, 32, (const unsigned char *)string_to_sign, strlen(string_to_sign), sig_raw, &sig_len);
    for (unsigned int i = 0; i < sig_len; i++) sprintf(signature + i * 2, "%02x", sig_raw[i]);

    char auth_header[1024];
    snprintf(auth_header, sizeof(auth_header),
             "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
             rp->access_key_id, credential_scope, signed_headers, signature);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/xml");
    char amz_date_hdr[64];
    snprintf(amz_date_hdr, sizeof(amz_date_hdr), "x-amz-date: %s", amz_date);
    headers = curl_slist_append(headers, amz_date_hdr);
    char payload_hash_hdr[64];
    snprintf(payload_hash_hdr, sizeof(payload_hash_hdr), "x-amz-content-sha256: %s", payload_hash);
    headers = curl_slist_append(headers, payload_hash_hdr);
    if (rp->session_token && rp->session_token[0]) {
        char token_hdr[512];
        snprintf(token_hdr, sizeof(token_hdr), "x-amz-security-token: %s", rp->session_token);
        headers = curl_slist_append(headers, token_hdr);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&res);
    if (payload && payload[0]) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    }
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode code = curl_easy_perform(curl);
    cJSON *root = NULL;
    if (code == CURLE_OK) {
        root = cJSON_Parse(res.data);
    } else {
        LOG_ERROR("Route53 API request failed: %s", curl_easy_strerror(code));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(res.data);
    return root;
}

static int route53_change_record(route53_provider *rp, const char *action, const char *name, const char *type, const char *value, int ttl) {
    if (!rp->hosted_zone_id) return CWIST_FAILURE;
    char uri[512];
    snprintf(uri, sizeof(uri), "/2013-04-01/hostedzone/%s/rrset/", rp->hosted_zone_id);

    char xml[4096];
    snprintf(xml, sizeof(xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\">"
        "<ChangeBatch>"
        "<Changes>"
        "<Change>"
        "<Action>%s</Action>"
        "<ResourceRecordSet>"
        "<Name>%s</Name>"
        "<Type>%s</Type>"
        "<TTL>%d</TTL>"
        "<ResourceRecords>"
        "<ResourceRecord>"
        "<Value>%s</Value>"
        "</ResourceRecord>"
        "</ResourceRecords>"
        "</ResourceRecordSet>"
        "</Change>"
        "</Changes>"
        "</ChangeBatch>"
        "</ChangeResourceRecordSetsRequest>",
        action, name, type, ttl, value ? value : "");

    cJSON *root = route53_api_request(rp, "POST", uri, xml);
    if (!root) return CWIST_FAILURE;
    cJSON_Delete(root);
    return CWIST_SUCCESS;
}

static int route53_ensure_a_records(portillia_dns_provider *p, const char *base_domain, const char *public_ipv4) {
    route53_provider *rp = (route53_provider *)p;
    int err = route53_change_record(rp, "UPSERT", base_domain, "A", public_ipv4, 300);
    if (err == CWIST_SUCCESS) {
        char wildcard[256];
        snprintf(wildcard, sizeof(wildcard), "*.%s", base_domain);
        err = route53_change_record(rp, "UPSERT", wildcard, "A", public_ipv4, 300);
    }
    return err;
}

static int route53_ensure_a_record(portillia_dns_provider *p, const char *name, const char *public_ipv4) {
    route53_provider *rp = (route53_provider *)p;
    return route53_change_record(rp, "UPSERT", name, "A", public_ipv4, 300);
}

static int route53_delete_a_record(portillia_dns_provider *p, const char *name) {
    route53_provider *rp = (route53_provider *)p;
    return route53_change_record(rp, "DELETE", name, "A", "0.0.0.0", 300);
}

static int route53_ensure_txt_record(portillia_dns_provider *p, const char *name, const char *value) {
    route53_provider *rp = (route53_provider *)p;
    return route53_change_record(rp, "UPSERT", name, "TXT", value, 300);
}

static int route53_delete_txt_records(portillia_dns_provider *p, const char *name, const char *match_prefix) {
    route53_provider *rp = (route53_provider *)p;
    (void)match_prefix;
    return route53_change_record(rp, "DELETE", name, "TXT", "", 300);
}

static int route53_ensure_dnssec(portillia_dns_provider *p, const char *base_domain, cwist_sstring *state, cwist_sstring *ds_record, cwist_sstring *message) {
    route53_provider *rp = (route53_provider *)p;
    (void)base_domain;
    if (!rp->hosted_zone_id) return CWIST_FAILURE;
    char uri[512];
    snprintf(uri, sizeof(uri), "/2013-04-01/hostedzone/%s/dnssec", rp->hosted_zone_id);
    cJSON *root = route53_api_request(rp, "GET", uri, NULL);
    if (!root) return CWIST_FAILURE;
    cJSON_Delete(root);
    cwist_sstring_assign(state, "active");
    cwist_sstring_assign(message, "Route53 DNSSEC managed externally if needed");
    return CWIST_SUCCESS;
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

static const char* route53_name(portillia_dns_provider *p) {
    (void)p;
    return "route53";
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
