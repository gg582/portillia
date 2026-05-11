/**
 * @file settings.c
 * @brief Complete implementation of persistent configuration management for the Portal relay server.
 * 
 * Now includes dynamic management of banned and approved identity lists.
 */

#include <portillia/portal/settings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

#define INITIAL_LIST_CAPACITY 8

/**
 * @brief Internal helper to resize string arrays.
 */
static char** resize_list(char **list, int *count, int *capacity, int new_item_count) {
    if (*count + new_item_count > *capacity) {
        *capacity *= 2;
        if (*count + new_item_count > *capacity) *capacity = *count + new_item_count;
        list = realloc(list, sizeof(char*) * (*capacity));
    }
    return list;
}

/**
 * @brief Loads settings from a JSON file.
 */
portillia_settings* portillia_settings_load(const char *path) {
    portillia_settings *s = calloc(1, sizeof(portillia_settings));
    if (!s) return NULL;
    s->path = strdup(path);
    s->approval_mode = strdup("auto");
    s->landing_page_enabled = true;
    s->default_bps_limit = 0;
    s->udp_enabled = true;
    s->tcp_port_enabled = true;
    s->trust_proxy_headers = false;

    s->banned_identities = calloc(INITIAL_LIST_CAPACITY, sizeof(char*));
    s->banned_count = 0;
    s->banned_capacity = INITIAL_LIST_CAPACITY;
    s->approved_identities = calloc(INITIAL_LIST_CAPACITY, sizeof(char*));
    s->approved_count = 0;
    s->approved_capacity = INITIAL_LIST_CAPACITY;
    s->trusted_proxy_cidrs = calloc(INITIAL_LIST_CAPACITY, sizeof(char*));
    s->trusted_proxy_count = 0;
    s->trusted_proxy_capacity = INITIAL_LIST_CAPACITY;

    FILE *f = fopen(path, "rb");
    if (!f) return s;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(size + 1);
    if (data) {
        fread(data, 1, size, f);
        data[size] = 0;

        cJSON *root = cJSON_Parse(data);
        if (root) {
            cJSON *mode = cJSON_GetObjectItem(root, "approval_mode");
            if (mode) {
                free(s->approval_mode);
                s->approval_mode = strdup(mode->valuestring);
            }
            cJSON *landing = cJSON_GetObjectItem(root, "landing_page_enabled");
            if (landing) s->landing_page_enabled = cJSON_IsTrue(landing);
            
            cJSON *bps = cJSON_GetObjectItem(root, "default_bps_limit");
            if (bps) s->default_bps_limit = (int64_t)bps->valuedouble;

            cJSON *udp = cJSON_GetObjectItem(root, "udp_enabled");
            if (udp) s->udp_enabled = cJSON_IsTrue(udp);

            cJSON *tcp = cJSON_GetObjectItem(root, "tcp_port_enabled");
            if (tcp) s->tcp_port_enabled = cJSON_IsTrue(tcp);

            cJSON *trust_headers = cJSON_GetObjectItem(root, "trust_proxy_headers");
            if (trust_headers) s->trust_proxy_headers = cJSON_IsTrue(trust_headers);

            cJSON *ech_seed = cJSON_GetObjectItem(root, "encrypted_client_hello_seed");
            if (ech_seed && ech_seed->valuestring) s->encrypted_client_hello_seed = strdup(ech_seed->valuestring);

            // Load banned identities
            cJSON *banned_arr = cJSON_GetObjectItem(root, "banned_identities");
            if (cJSON_IsArray(banned_arr)) {
                s->banned_identities = resize_list(s->banned_identities, &s->banned_count, &s->banned_capacity, cJSON_GetArraySize(banned_arr));
                cJSON *item;
                cJSON_ArrayForEach(item, banned_arr) {
                    s->banned_identities[s->banned_count++] = strdup(item->valuestring);
                }
            }
            // Load approved identities
            cJSON *approved_arr = cJSON_GetObjectItem(root, "approved_identities");
            if (cJSON_IsArray(approved_arr)) {
                s->approved_identities = resize_list(s->approved_identities, &s->approved_count, &s->approved_capacity, cJSON_GetArraySize(approved_arr));
                cJSON *item;
                cJSON_ArrayForEach(item, approved_arr) {
                    s->approved_identities[s->approved_count++] = strdup(item->valuestring);
                }
            }
            // Load trusted proxy CIDRs
            cJSON *cidrs_arr = cJSON_GetObjectItem(root, "trusted_proxy_cidrs");
            if (cJSON_IsArray(cidrs_arr)) {
                s->trusted_proxy_cidrs = resize_list(s->trusted_proxy_cidrs, &s->trusted_proxy_count, &s->trusted_proxy_capacity, cJSON_GetArraySize(cidrs_arr));
                cJSON *item;
                cJSON_ArrayForEach(item, cidrs_arr) {
                    s->trusted_proxy_cidrs[s->trusted_proxy_count++] = strdup(item->valuestring);
                }
            }

            cJSON_Delete(root);
        }
        free(data);
    }
    fclose(f);
    return s;
}

/**
 * @brief Saves current settings to a JSON file.
 */
void portillia_settings_save(const char *path, portillia_settings *s) {
    if (!s) return;
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "approval_mode", s->approval_mode);
    cJSON_AddBoolToObject(root, "landing_page_enabled", s->landing_page_enabled);
    cJSON_AddNumberToObject(root, "default_bps_limit", (double)s->default_bps_limit);
    cJSON_AddBoolToObject(root, "udp_enabled", s->udp_enabled);
    cJSON_AddBoolToObject(root, "tcp_port_enabled", s->tcp_port_enabled);
    cJSON_AddBoolToObject(root, "trust_proxy_headers", s->trust_proxy_headers);
    if (s->encrypted_client_hello_seed) {
        cJSON_AddStringToObject(root, "encrypted_client_hello_seed", s->encrypted_client_hello_seed);
    }

    cJSON *banned_arr = cJSON_CreateArray();
    for (int i = 0; i < s->banned_count; i++) {
        cJSON_AddItemToArray(banned_arr, cJSON_CreateString(s->banned_identities[i]));
    }
    cJSON_AddItemToObject(root, "banned_identities", banned_arr);

    cJSON *approved_arr = cJSON_CreateArray();
    for (int i = 0; i < s->approved_count; i++) {
        cJSON_AddItemToArray(approved_arr, cJSON_CreateString(s->approved_identities[i]));
    }
    cJSON_AddItemToObject(root, "approved_identities", approved_arr);

    cJSON *cidrs_arr = cJSON_CreateArray();
    for (int i = 0; i < s->trusted_proxy_count; i++) {
        cJSON_AddItemToArray(cidrs_arr, cJSON_CreateString(s->trusted_proxy_cidrs[i]));
    }
    cJSON_AddItemToObject(root, "trusted_proxy_cidrs", cidrs_arr);

    char *json = cJSON_Print(root);
    if (json) {
        FILE *f = fopen(path, "wb");
        if (f) {
            fputs(json, f);
            fclose(f);
        }
        free(json);
    }
    cJSON_Delete(root);
}

/**
 * @brief Frees a settings structure.
 */
void portillia_settings_free(portillia_settings *s) {
    if (!s) return;
    free(s->approval_mode);
    for (int i = 0; i < s->banned_count; i++) free(s->banned_identities[i]);
    free(s->banned_identities);
    for (int i = 0; i < s->approved_count; i++) free(s->approved_identities[i]);
    free(s->approved_identities);
    for (int i = 0; i < s->trusted_proxy_count; i++) free(s->trusted_proxy_cidrs[i]);
    free(s->trusted_proxy_cidrs);
    free(s->encrypted_client_hello_seed);
    free(s);
}

/**
 * @brief Adds an identity to the ban list.
 */
void portillia_settings_ban_identity(portillia_settings *s, const char *addr) {
    if (!s || !addr) return;
    // Check if already banned
    for (int i = 0; i < s->banned_count; i++) {
        if (strcmp(s->banned_identities[i], addr) == 0) return;
    }
    s->banned_identities = resize_list(s->banned_identities, &s->banned_count, &s->banned_capacity, 1);
    s->banned_identities[s->banned_count++] = strdup(addr);
}

/**
 * @brief Removes an identity from the ban list.
 */
void portillia_settings_unban_identity(portillia_settings *s, const char *addr) {
    if (!s || !addr) return;
    for (int i = 0; i < s->banned_count; i++) {
        if (strcmp(s->banned_identities[i], addr) == 0) {
            free(s->banned_identities[i]);
            s->banned_identities[i] = s->banned_identities[--s->banned_count];
            return;
        }
    }
}

/**
 * @brief Manually approves an identity.
 */
void portillia_settings_approve_identity(portillia_settings *s, const char *addr) {
    if (!s || !addr) return;
    // Check if already approved
    for (int i = 0; i < s->approved_count; i++) {
        if (strcmp(s->approved_identities[i], addr) == 0) return;
    }
    s->approved_identities = resize_list(s->approved_identities, &s->approved_count, &s->approved_capacity, 1);
    s->approved_identities[s->approved_count++] = strdup(addr);
}
