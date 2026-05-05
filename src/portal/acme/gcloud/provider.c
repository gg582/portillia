#include <portillia/portal/acme/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <portillia/utils/log.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define GCLOUD_DNS_API_BASE "https://dns.googleapis.com/dns/v1"
#define GCLOUD_TOKEN_URL "https://oauth2.googleapis.com/token"

typedef struct {
    portillia_dns_provider base;
    char *project_id;
    char *managed_zone;
    char *access_token;
    time_t token_expires_at;
} gcloud_provider;

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

static char *base64url_encode(const uint8_t *data, size_t len) {
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, (int)len);
    BIO_flush(bio);
    BUF_MEM *buf;
    BIO_get_mem_ptr(bio, &buf);
    char *out = malloc(buf->length + 1);
    if (out) {
        memcpy(out, buf->data, buf->length);
        out[buf->length] = '\0';
        /* Replace + with -, / with _, remove padding */
        for (size_t i = 0; i < buf->length; i++) {
            if (out[i] == '+') out[i] = '-';
            else if (out[i] == '/') out[i] = '_';
        }
        /* Strip trailing = */
        size_t olen = strlen(out);
        while (olen > 0 && out[olen-1] == '=') out[--olen] = '\0';
    }
    BIO_free_all(bio);
    return out;
}

static char *load_service_account_json(void) {
    const char *path = getenv("GOOGLE_APPLICATION_CREDENTIALS");
    if (!path) return NULL;
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 65536) { fclose(f); return NULL; }
    char *buf = malloc(sz + 1);
    if (!buf || fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

static int gcloud_refresh_token(gcloud_provider *gp) {
    char *sa_json = load_service_account_json();
    if (!sa_json) {
        LOG_WARN("GCloud: No service account found. Set GOOGLE_APPLICATION_CREDENTIALS.");
        return CWIST_FAILURE;
    }
    cJSON *root = cJSON_Parse(sa_json);
    free(sa_json);
    if (!root) return CWIST_FAILURE;

    cJSON *client_email = cJSON_GetObjectItem(root, "client_email");
    cJSON *private_key = cJSON_GetObjectItem(root, "private_key");
    if (!cJSON_IsString(client_email) || !cJSON_IsString(private_key)) {
        cJSON_Delete(root);
        return CWIST_FAILURE;
    }

    time_t now = time(NULL);
    char claim_set[1024];
    snprintf(claim_set, sizeof(claim_set),
        "{\"iss\":\"%s\",\"scope\":\"https://www.googleapis.com/auth/cloud-platform\",\"aud\":\"%s\",\"iat\":%ld,\"exp\":%ld}",
        client_email->valuestring, GCLOUD_TOKEN_URL, (long)now, (long)(now + 3600));

    char header[128];
    snprintf(header, sizeof(header), "{\"alg\":\"RS256\",\"typ\":\"JWT\"}");

    char *header_b64 = base64url_encode((const uint8_t *)header, strlen(header));
    char *claim_b64 = base64url_encode((const uint8_t *)claim_set, strlen(claim_set));
    if (!header_b64 || !claim_b64) {
        free(header_b64); free(claim_b64);
        cJSON_Delete(root);
        return CWIST_FAILURE;
    }

    char signing_input[4096];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", header_b64, claim_b64);

    BIO *bio = BIO_new_mem_buf(private_key->valuestring, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        free(header_b64); free(claim_b64);
        cJSON_Delete(root);
        return CWIST_FAILURE;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char sig_raw[512];
    size_t sig_len = 0;
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(ctx, signing_input, strlen(signing_input));
    EVP_DigestSignFinal(ctx, sig_raw, &sig_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    char *sig_b64 = base64url_encode(sig_raw, sig_len);
    if (!sig_b64) {
        free(header_b64); free(claim_b64);
        cJSON_Delete(root);
        return CWIST_FAILURE;
    }

    char jwt[8192];
    snprintf(jwt, sizeof(jwt), "%s.%s.%s", header_b64, claim_b64, sig_b64);
    free(header_b64); free(claim_b64); free(sig_b64);
    cJSON_Delete(root);

    CURL *curl = curl_easy_init();
    if (!curl) return CWIST_FAILURE;
    struct curl_response res = { .data = malloc(1), .size = 0 };
    res.data[0] = '\0';

    char postfields[8192];
    snprintf(postfields, sizeof(postfields),
        "grant_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Ajwt-bearer&assertion=%s", jwt);

    curl_easy_setopt(curl, CURLOPT_URL, GCLOUD_TOKEN_URL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    CURLcode code = curl_easy_perform(curl);
    int result = CWIST_FAILURE;
    if (code == CURLE_OK) {
        cJSON *tok = cJSON_Parse(res.data);
        if (tok) {
            cJSON *access_token = cJSON_GetObjectItem(tok, "access_token");
            cJSON *expires_in = cJSON_GetObjectItem(tok, "expires_in");
            if (cJSON_IsString(access_token)) {
                free(gp->access_token);
                gp->access_token = strdup(access_token->valuestring);
                gp->token_expires_at = time(NULL) + (cJSON_IsNumber(expires_in) ? (int)expires_in->valuedouble : 3600);
                result = CWIST_SUCCESS;
            }
            cJSON_Delete(tok);
        }
    }
    curl_easy_cleanup(curl);
    free(res.data);
    return result;
}

static int gcloud_ensure_token(gcloud_provider *gp) {
    if (gp->access_token && gp->token_expires_at > time(NULL) + 60) return CWIST_SUCCESS;
    return gcloud_refresh_token(gp);
}

static cJSON* gcloud_api_request(gcloud_provider *gp, const char *method, const char *endpoint, const char *body) {
    if (gcloud_ensure_token(gp) != CWIST_SUCCESS) return NULL;
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct curl_response res = { .data = malloc(1), .size = 0 };
    res.data[0] = '\0';

    char url[2048];
    snprintf(url, sizeof(url), "%s%s", GCLOUD_DNS_API_BASE, endpoint);

    struct curl_slist *headers = NULL;
    char auth_hdr[4096];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", gp->access_token);
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    if (body && body[0]) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode code = curl_easy_perform(curl);
    cJSON *root = NULL;
    if (code == CURLE_OK) {
        root = cJSON_Parse(res.data);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(res.data);
    return root;
}

static int gcloud_dns_change(gcloud_provider *gp, const char *json_body) {
    char endpoint[1024];
    snprintf(endpoint, sizeof(endpoint), "/projects/%s/managedZones/%s/changes", gp->project_id, gp->managed_zone);
    cJSON *root = gcloud_api_request(gp, "POST", endpoint, json_body);
    if (!root) return CWIST_FAILURE;
    cJSON *status = cJSON_GetObjectItem(root, "status");
    int ok = (status && cJSON_IsString(status) && strcmp(status->valuestring, "pending") == 0) ? CWIST_SUCCESS : CWIST_FAILURE;
    cJSON_Delete(root);
    return ok;
}

static int gcloud_ensure_a_records(portillia_dns_provider *p, const char *base_domain, const char *public_ipv4) {
    gcloud_provider *gp = (gcloud_provider *)p;
    cJSON *root = cJSON_CreateObject();
    cJSON *additions = cJSON_CreateArray();
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "name", base_domain);
    cJSON_AddStringToObject(rec, "type", "A");
    cJSON_AddNumberToObject(rec, "ttl", 300);
    cJSON *rrdatas = cJSON_CreateArray();
    cJSON_AddItemToArray(rrdatas, cJSON_CreateString(public_ipv4));
    cJSON_AddItemToObject(rec, "rrdatas", rrdatas);
    cJSON_AddItemToArray(additions, rec);
    cJSON_AddItemToObject(root, "additions", additions);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    int err = gcloud_dns_change(gp, json);
    free(json);
    if (err == CWIST_SUCCESS) {
        cJSON *root2 = cJSON_CreateObject();
        cJSON *additions2 = cJSON_CreateArray();
        cJSON *rec2 = cJSON_CreateObject();
        char wildcard[256];
        snprintf(wildcard, sizeof(wildcard), "*.%s", base_domain);
        cJSON_AddStringToObject(rec2, "name", wildcard);
        cJSON_AddStringToObject(rec2, "type", "A");
        cJSON_AddNumberToObject(rec2, "ttl", 300);
        cJSON *rrdatas2 = cJSON_CreateArray();
        cJSON_AddItemToArray(rrdatas2, cJSON_CreateString(public_ipv4));
        cJSON_AddItemToObject(rec2, "rrdatas", rrdatas2);
        cJSON_AddItemToArray(additions2, rec2);
        cJSON_AddItemToObject(root2, "additions", additions2);
        char *json2 = cJSON_PrintUnformatted(root2);
        cJSON_Delete(root2);
        err = gcloud_dns_change(gp, json2);
        free(json2);
    }
    return err;
}

static int gcloud_ensure_a_record(portillia_dns_provider *p, const char *name, const char *public_ipv4) {
    gcloud_provider *gp = (gcloud_provider *)p;
    cJSON *root = cJSON_CreateObject();
    cJSON *additions = cJSON_CreateArray();
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "name", name);
    cJSON_AddStringToObject(rec, "type", "A");
    cJSON_AddNumberToObject(rec, "ttl", 300);
    cJSON *rrdatas = cJSON_CreateArray();
    cJSON_AddItemToArray(rrdatas, cJSON_CreateString(public_ipv4));
    cJSON_AddItemToObject(rec, "rrdatas", rrdatas);
    cJSON_AddItemToArray(additions, rec);
    cJSON_AddItemToObject(root, "additions", additions);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    int err = gcloud_dns_change(gp, json);
    free(json);
    return err;
}

static int gcloud_delete_a_record(portillia_dns_provider *p, const char *name) {
    gcloud_provider *gp = (gcloud_provider *)p;
    cJSON *root = cJSON_CreateObject();
    cJSON *deletions = cJSON_CreateArray();
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "name", name);
    cJSON_AddStringToObject(rec, "type", "A");
    cJSON_AddNumberToObject(rec, "ttl", 300);
    cJSON *rrdatas = cJSON_CreateArray();
    cJSON_AddItemToArray(rrdatas, cJSON_CreateString("0.0.0.0"));
    cJSON_AddItemToObject(rec, "rrdatas", rrdatas);
    cJSON_AddItemToArray(deletions, rec);
    cJSON_AddItemToObject(root, "deletions", deletions);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    int err = gcloud_dns_change(gp, json);
    free(json);
    return err;
}

static int gcloud_ensure_txt_record(portillia_dns_provider *p, const char *name, const char *value) {
    gcloud_provider *gp = (gcloud_provider *)p;
    cJSON *root = cJSON_CreateObject();
    cJSON *additions = cJSON_CreateArray();
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "name", name);
    cJSON_AddStringToObject(rec, "type", "TXT");
    cJSON_AddNumberToObject(rec, "ttl", 300);
    cJSON *rrdatas = cJSON_CreateArray();
    cJSON_AddItemToArray(rrdatas, cJSON_CreateString(value));
    cJSON_AddItemToObject(rec, "rrdatas", rrdatas);
    cJSON_AddItemToArray(additions, rec);
    cJSON_AddItemToObject(root, "additions", additions);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    int err = gcloud_dns_change(gp, json);
    free(json);
    return err;
}

static int gcloud_delete_txt_records(portillia_dns_provider *p, const char *name, const char *match_prefix) {
    gcloud_provider *gp = (gcloud_provider *)p;
    (void)match_prefix;
    cJSON *root = cJSON_CreateObject();
    cJSON *deletions = cJSON_CreateArray();
    cJSON *rec = cJSON_CreateObject();
    cJSON_AddStringToObject(rec, "name", name);
    cJSON_AddStringToObject(rec, "type", "TXT");
    cJSON_AddNumberToObject(rec, "ttl", 300);
    cJSON *rrdatas = cJSON_CreateArray();
    cJSON_AddItemToArray(rrdatas, cJSON_CreateString(""));
    cJSON_AddItemToObject(rec, "rrdatas", rrdatas);
    cJSON_AddItemToArray(deletions, rec);
    cJSON_AddItemToObject(root, "deletions", deletions);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    int err = gcloud_dns_change(gp, json);
    free(json);
    return err;
}

static int gcloud_ensure_dnssec(portillia_dns_provider *p, const char *base_domain, cwist_sstring *state, cwist_sstring *ds_record, cwist_sstring *message) {
    gcloud_provider *gp = (gcloud_provider *)p;
    (void)base_domain;
    char endpoint[1024];
    snprintf(endpoint, sizeof(endpoint), "/projects/%s/managedZones/%s", gp->project_id, gp->managed_zone);
    cJSON *root = gcloud_api_request(gp, "GET", endpoint, NULL);
    if (!root) return CWIST_FAILURE;
    cJSON *dnssec = cJSON_GetObjectItem(root, "dnssecConfig");
    if (dnssec) {
        cJSON *st = cJSON_GetObjectItem(dnssec, "state");
        if (st && cJSON_IsString(st)) cwist_sstring_assign(state, st->valuestring);
    }
    cJSON_Delete(root);
    cwist_sstring_assign(message, "GCP Cloud DNS DNSSEC state queried");
    return CWIST_SUCCESS;
}

static void gcloud_destroy(portillia_dns_provider *p) {
    gcloud_provider *gp = (gcloud_provider *)p;
    free(gp->project_id);
    free(gp->managed_zone);
    free(gp->access_token);
    free(gp);
}

static const char* gcloud_name(portillia_dns_provider *p) {
    (void)p;
    return "gcloud";
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
