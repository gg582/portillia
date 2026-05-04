#include <portillia/portal/discovery/discovery.h>
#include <ttak/ttak.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <portillia/utils/log.h>
#include <unistd.h>

extern char* portillia_registry_to_json();

portillia_relay_set* portillia_relay_set_new() {
    portillia_relay_set *set = calloc(1, sizeof(portillia_relay_set));
    pthread_mutex_init(&set->mu, NULL);
    return set;
}

void portillia_relay_set_upsert(portillia_relay_set *set, portillia_relay_descriptor desc) {
    pthread_mutex_lock(&set->mu);
    for (int i = 0; i < set->count; i++) {
        if (strcmp(set->relays[i].descriptor.api_https_addr->data, desc.api_https_addr->data) == 0) {
            // Update existing
            // In a real version, we'd check IssuedAt for rollback defense
            set->relays[i].descriptor.expires_at = desc.expires_at;
            set->relays[i].descriptor.active_connections = desc.active_connections;
            set->relays[i].descriptor.tcp_bps = desc.tcp_bps;
            pthread_mutex_unlock(&set->mu);
            return;
        }
    }
    if (set->count < MAX_RELAYS) {
        set->relays[set->count].descriptor.api_https_addr = cwist_sstring_create();
        cwist_sstring_assign(set->relays[set->count].descriptor.api_https_addr, desc.api_https_addr->data);
        set->relays[set->count].descriptor.expires_at = desc.expires_at;
        set->relays[set->count].descriptor.active_connections = desc.active_connections;
        set->count++;
    }
    pthread_mutex_unlock(&set->mu);
}

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

void portillia_discovery_poll(discovery_config *cfg, const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    struct curl_response res = { .data = malloc(1), .size = 0 };
    res.data[0] = '\0';

    char full_url[1024];
    snprintf(full_url, sizeof(full_url), "%s/discovery", url);

    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&res);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode code = curl_easy_perform(curl);
    if (code == CURLE_OK) {
        cJSON *root = cJSON_Parse(res.data);
        if (root) {
            cJSON *relays = cJSON_GetObjectItem(root, "relays");
            if (cJSON_IsArray(relays)) {
                int size = cJSON_GetArraySize(relays);
                for (int i = 0; i < size; i++) {
                    cJSON *item = cJSON_GetArrayItem(relays, i);
                    cJSON *api_addr = cJSON_GetObjectItem(item, "api_https_addr");
                    cJSON *wg_pubkey = cJSON_GetObjectItem(item, "wireguard_public_key");
                    if (api_addr && api_addr->valuestring) {
                        portillia_relay_descriptor d = {0};
                        d.api_https_addr = cwist_sstring_create();
                        cwist_sstring_assign(d.api_https_addr, api_addr->valuestring);
                        if (wg_pubkey && wg_pubkey->valuestring) {
                            d.wireguard_public_key = cwist_sstring_create();
                            cwist_sstring_assign(d.wireguard_public_key, wg_pubkey->valuestring);
                        }
                        d.expires_at = time(NULL) + 60;
                        portillia_relay_set_upsert(cfg->relay_set, d);
                        cwist_sstring_destroy(d.api_https_addr);
                        if (d.wireguard_public_key) cwist_sstring_destroy(d.wireguard_public_key);
                    }
                }
            }
            cJSON_Delete(root);
        }
    }

    free(res.data);
    curl_easy_cleanup(curl);
}

void portillia_discovery_announce(discovery_config *cfg, portillia_relay_descriptor *desc) {
    // Periodic poll of bootstraps
    if (cfg->bootstrap_urls) {
        char *copy = strdup(cfg->bootstrap_urls);
        char *token = strtok(copy, ",");
        while (token) {
            if (strcmp(token, cfg->relay_url) != 0) {
                portillia_discovery_poll(cfg, token);
                
                // Also send self-announce
                CURL *curl = curl_easy_init();
                char announce_url[1024];
                snprintf(announce_url, sizeof(announce_url), "%s/discovery/announce", token);
                
                cJSON *root = cJSON_CreateObject();
                cJSON_AddStringToObject(root, "protocol_version", "7");
                cJSON *d = cJSON_CreateObject();
                cJSON_AddStringToObject(d, "api_https_addr", desc->api_https_addr->data);
                cJSON_AddNumberToObject(d, "active_connections", (double)desc->active_connections);
                cJSON_AddItemToObject(root, "descriptor", d);
                
                char *json = cJSON_PrintUnformatted(root);
                
                curl_easy_setopt(curl, CURLOPT_URL, announce_url);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
                CURLcode code = curl_easy_perform(curl);
                if (code == CURLE_OK) {
                    long status = 0;
                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
                    if (status >= 200 && status < 300) {
                        LOG_INFO("relay discovery announce succeeded relay=%s", token);
                    } else {
                        LOG_WARN("relay discovery announce failed error=\"http status %ld\" relay=%s", status, token);
                    }
                } else {
                    LOG_WARN("relay discovery announce failed error=\"%s\" relay=%s", curl_easy_strerror(code), token);
                }
                
                free(json);
                cJSON_Delete(root);
                curl_easy_cleanup(curl);
            }
            token = strtok(NULL, ",");
        }
        free(copy);
    }
}

extern int64_t portillia_proxy_get_active_conns();
extern double portillia_proxy_get_current_bps();

static void discovery_task(ttak_task_t *task, void *arg) {
    (void)task;
    discovery_config *cfg = (discovery_config *)arg;
    if (!cfg || !cfg->relay_url) {
        return;
    }

    portillia_relay_descriptor desc;
    desc.api_https_addr = cwist_sstring_create();
    cwist_sstring_assign(desc.api_https_addr, (char *)cfg->relay_url);
    desc.version = cwist_sstring_create();
    cwist_sstring_assign(desc.version, (char *)PORTILLIA_RELEASE_VERSION);
    
    desc.active_connections = portillia_proxy_get_active_conns();
    desc.tcp_bps = portillia_proxy_get_current_bps();

    // WireGuard Info
    desc.wireguard_public_key = cwist_sstring_create();
    cwist_sstring_assign(desc.wireguard_public_key, (char *)"mock_wg_pubkey");
    desc.wireguard_port = 51820;
    desc.supports_overlay = true;

    desc.signature = cwist_sstring_create(); 
    cwist_sstring_assign(desc.signature, (char *)"mock_signature");
    
    portillia_discovery_announce(cfg, &desc);
    
    cwist_sstring_destroy(desc.api_https_addr);
    cwist_sstring_destroy(desc.version);
    cwist_sstring_destroy(desc.signature);

}

void *discovery_maintenance_loop(void *arg) {
    discovery_config *cfg = (discovery_config *)arg;
    while (1) {
        discovery_task(NULL, cfg);
        sleep(30);
    }
    return NULL;
}
