#include <portillia/portal/acme/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <cwist/core/mem/alloc.h>
#include <portillia/utils/log.h>

#define CLOUDFLARE_API_BASE "https://api.cloudflare.com/client/v4"

typedef struct {
    portillia_dns_provider base;
    char *token;
} cloudflare_provider;

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

static cJSON* cloudflare_api_request(const char *token, const char *method, const char *endpoint, cJSON *body) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    struct curl_response res = { .data = malloc(1), .size = 0 };
    res.data[0] = '\0';

    char url[1024];
    snprintf(url, sizeof(url), "%s%s", CLOUDFLARE_API_BASE, endpoint);

    struct curl_slist *headers = NULL;
    char auth_header[256];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&res);

    char *json_str = NULL;
    if (body) {
        json_str = cJSON_PrintUnformatted(body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    }

    CURLcode code = curl_easy_perform(curl);
    cJSON *root = NULL;
    if (code == CURLE_OK) {
        root = cJSON_Parse(res.data);
    } else {
        LOG_ERROR("Cloudflare API request failed: %s", curl_easy_strerror(code));
    }

    if (json_str) {
        free(json_str);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(res.data);
    return root;
}

static char* find_zone_id(const char *token, const char *domain) {
    char temp[256];
    strncpy(temp, domain, sizeof(temp));
    temp[sizeof(temp)-1] = '\0';

    char *parts[32];
    int count = 0;
    char *p = strtok(temp, ".");
    while (p && count < 32) {
        parts[count++] = p;
        p = strtok(NULL, ".");
    }

    for (int i = 0; i < count - 1; i++) {
        char candidate[256] = "";
        for (int j = i; j < count; j++) {
            strcat(candidate, parts[j]);
            if (j < count - 1) strcat(candidate, ".");
        }

        char endpoint[512];
        snprintf(endpoint, sizeof(endpoint), "/zones?name=%s", candidate);
        cJSON *res = cloudflare_api_request(token, "GET", endpoint, NULL);
        if (res) {
            cJSON *success = cJSON_GetObjectItem(res, "success");
            if (cJSON_IsTrue(success)) {
                cJSON *result = cJSON_GetObjectItem(res, "result");
                if (cJSON_IsArray(result) && cJSON_GetArraySize(result) > 0) {
                    cJSON *zone = cJSON_GetArrayItem(result, 0);
                    char *id = strdup(cJSON_GetObjectItem(zone, "id")->valuestring);
                    cJSON_Delete(res);
                    return id;
                }
            }
            cJSON_Delete(res);
        }
    }
    return NULL;
}

static const char* cloudflare_name(portillia_dns_provider *p) {
    return "cloudflare";
}

static int cloudflare_ensure_dns_record(cloudflare_provider *cp, const char *zone_id, const char *name, const char *type, const char *content) {
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/zones/%s/dns_records?name=%s&type=%s", zone_id, name, type);
    cJSON *res = cloudflare_api_request(cp->token, "GET", endpoint, NULL);
    if (!res) return CWIST_FAILURE;

    cJSON *result = cJSON_GetObjectItem(res, "result");
    if (cJSON_IsArray(result) && cJSON_GetArraySize(result) > 0) {
        cJSON *record = cJSON_GetArrayItem(result, 0);
        char *existing_content = cJSON_GetObjectItem(record, "content")->valuestring;
        if (strcmp(existing_content, content) == 0) {
            cJSON_Delete(res);
            return CWIST_SUCCESS;
        }

        char *record_id = cJSON_GetObjectItem(record, "id")->valuestring;
        snprintf(endpoint, sizeof(endpoint), "/zones/%s/dns_records/%s", zone_id, record_id);
        cJSON *body = cJSON_CreateObject();
        cJSON_AddStringToObject(body, "type", type);
        cJSON_AddStringToObject(body, "name", name);
        cJSON_AddStringToObject(body, "content", content);
        cJSON_AddNumberToObject(body, "ttl", 1);
        if (strcmp(type, "A") == 0) cJSON_AddBoolToObject(body, "proxied", 0);
        
        cJSON *update_res = cloudflare_api_request(cp->token, "PUT", endpoint, body);
        cJSON_Delete(body);
        cJSON_Delete(res);
        if (update_res) {
            int err = cJSON_IsTrue(cJSON_GetObjectItem(update_res, "success")) ? CWIST_SUCCESS : CWIST_FAILURE;
            cJSON_Delete(update_res);
            return err;
        }
        return CWIST_FAILURE;
    }

    cJSON_Delete(res);
    snprintf(endpoint, sizeof(endpoint), "/zones/%s/dns_records", zone_id);
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "type", type);
    cJSON_AddStringToObject(body, "name", name);
    cJSON_AddStringToObject(body, "content", content);
    cJSON_AddNumberToObject(body, "ttl", 1);
    if (strcmp(type, "A") == 0) cJSON_AddBoolToObject(body, "proxied", 0);

    cJSON *create_res = cloudflare_api_request(cp->token, "POST", endpoint, body);
    cJSON_Delete(body);
    if (create_res) {
        int err = cJSON_IsTrue(cJSON_GetObjectItem(create_res, "success")) ? CWIST_SUCCESS : CWIST_FAILURE;
        cJSON_Delete(create_res);
        return err;
    }
    return CWIST_FAILURE;
}

static int cloudflare_ensure_a_records(portillia_dns_provider *p, const char *base_domain, const char *public_ipv4) {
    cloudflare_provider *cp = (cloudflare_provider *)p;
    char *zone_id = find_zone_id(cp->token, base_domain);
    if (!zone_id) return CWIST_FAILURE;

    int err = cloudflare_ensure_dns_record(cp, zone_id, base_domain, "A", public_ipv4);
    if (err == CWIST_SUCCESS) {
        char wildcard[256];
        snprintf(wildcard, sizeof(wildcard), "*.%s", base_domain);
        err = cloudflare_ensure_dns_record(cp, zone_id, wildcard, "A", public_ipv4);
    }

    free(zone_id);
    return err;
}

static int cloudflare_ensure_a_record(portillia_dns_provider *p, const char *name, const char *public_ipv4) {
    cloudflare_provider *cp = (cloudflare_provider *)p;
    char *zone_id = find_zone_id(cp->token, name);
    if (!zone_id) return CWIST_FAILURE;

    int err = cloudflare_ensure_dns_record(cp, zone_id, name, "A", public_ipv4);
    free(zone_id);
    return err;
}

static int cloudflare_delete_a_record(portillia_dns_provider *p, const char *name) {
    cloudflare_provider *cp = (cloudflare_provider *)p;
    char *zone_id = find_zone_id(cp->token, name);
    if (!zone_id) return CWIST_FAILURE;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/zones/%s/dns_records?name=%s&type=A", zone_id, name);
    cJSON *res = cloudflare_api_request(cp->token, "GET", endpoint, NULL);
    if (res) {
        cJSON *result = cJSON_GetObjectItem(res, "result");
        if (cJSON_IsArray(result)) {
            for (int i = 0; i < cJSON_GetArraySize(result); i++) {
                cJSON *record = cJSON_GetArrayItem(result, i);
                char *record_id = cJSON_GetObjectItem(record, "id")->valuestring;
                snprintf(endpoint, sizeof(endpoint), "/zones/%s/dns_records/%s", zone_id, record_id);
                cJSON *del_res = cloudflare_api_request(cp->token, "DELETE", endpoint, NULL);
                if (del_res) cJSON_Delete(del_res);
            }
        }
        cJSON_Delete(res);
    }

    free(zone_id);
    return CWIST_SUCCESS;
}

static int cloudflare_ensure_txt_record(portillia_dns_provider *p, const char *name, const char *value) {
    cloudflare_provider *cp = (cloudflare_provider *)p;
    char *zone_id = find_zone_id(cp->token, name);
    if (!zone_id) return CWIST_FAILURE;

    int err = cloudflare_ensure_dns_record(cp, zone_id, name, "TXT", value);
    free(zone_id);
    return err;
}

static int cloudflare_delete_txt_records(portillia_dns_provider *p, const char *name, const char *match_prefix) {
    cloudflare_provider *cp = (cloudflare_provider *)p;
    char *zone_id = find_zone_id(cp->token, name);
    if (!zone_id) return CWIST_FAILURE;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/zones/%s/dns_records?name=%s&type=TXT", zone_id, name);
    cJSON *res = cloudflare_api_request(cp->token, "GET", endpoint, NULL);
    if (res) {
        cJSON *result = cJSON_GetObjectItem(res, "result");
        if (cJSON_IsArray(result)) {
            for (int i = 0; i < cJSON_GetArraySize(result); i++) {
                cJSON *record = cJSON_GetArrayItem(result, i);
                char *content = cJSON_GetObjectItem(record, "content")->valuestring;
                if (strncmp(content, match_prefix, strlen(match_prefix)) == 0) {
                    char *record_id = cJSON_GetObjectItem(record, "id")->valuestring;
                    snprintf(endpoint, sizeof(endpoint), "/zones/%s/dns_records/%s", zone_id, record_id);
                    cJSON *del_res = cloudflare_api_request(cp->token, "DELETE", endpoint, NULL);
                    if (del_res) cJSON_Delete(del_res);
                }
            }
        }
        cJSON_Delete(res);
    }

    free(zone_id);
    return CWIST_SUCCESS;
}

static int cloudflare_ensure_dnssec(portillia_dns_provider *p, const char *base_domain, cwist_sstring *state, cwist_sstring *ds_record, cwist_sstring *message) {
    cloudflare_provider *cp = (cloudflare_provider *)p;
    char *zone_id = find_zone_id(cp->token, base_domain);
    if (!zone_id) return CWIST_FAILURE;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/zones/%s/dnssec", zone_id);
    cJSON *res = cloudflare_api_request(cp->token, "GET", endpoint, NULL);
    if (!res) {
        free(zone_id);
        return CWIST_FAILURE;
    }

    cJSON *result = cJSON_GetObjectItem(res, "result");
    char *status = cJSON_GetObjectItem(result, "status")->valuestring;
    if (strcmp(status, "active") != 0 && strcmp(status, "pending") != 0) {
        cJSON *body = cJSON_CreateObject();
        cJSON_AddStringToObject(body, "status", "active");
        cJSON *update_res = cloudflare_api_request(cp->token, "PATCH", endpoint, body);
        cJSON_Delete(body);
        if (update_res) {
            cJSON_Delete(res);
            res = update_res;
            result = cJSON_GetObjectItem(res, "result");
            status = cJSON_GetObjectItem(result, "status")->valuestring;
        }
    }

    cwist_sstring_assign(state, status);
    cJSON *ds = cJSON_GetObjectItem(result, "ds");
    if (cJSON_IsString(ds)) {
        cwist_sstring_assign(ds_record, ds->valuestring);
        cwist_sstring_assign(message, "publish the DS record at the registrar if Cloudflare Registrar does not manage the zone");
    }

    cJSON_Delete(res);
    free(zone_id);
    return CWIST_SUCCESS;
}

static void cloudflare_destroy(portillia_dns_provider *p) {
    cloudflare_provider *cp = (cloudflare_provider *)p;
    free(cp->token);
    free(cp);
}

portillia_dns_provider* portillia_cloudflare_new(const char *token) {
    cloudflare_provider *cp = calloc(1, sizeof(cloudflare_provider));
    cp->base.name = cloudflare_name;
    cp->base.ensure_a_records = cloudflare_ensure_a_records;
    cp->base.ensure_a_record = cloudflare_ensure_a_record;
    cp->base.delete_a_record = cloudflare_delete_a_record;
    cp->base.ensure_txt_record = cloudflare_ensure_txt_record;
    cp->base.delete_txt_records = cloudflare_delete_txt_records;
    cp->base.ensure_dnssec = cloudflare_ensure_dnssec;
    cp->base.destroy = cloudflare_destroy;
    cp->token = strdup(token);
    return &cp->base;
}
