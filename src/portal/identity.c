#include <portillia/portal/identity.h>
#include <portillia/utils/log.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "portal_bridge.h"

static char *join_path(const char *dir, const char *file) {
    size_t dir_len = strlen(dir);
    int need_sep = (dir_len == 0 || dir[dir_len - 1] != '/');
    size_t total = dir_len + (need_sep ? 1 : 0) + strlen(file) + 1;
    char *path = malloc(total);
    if (!path) return NULL;
    snprintf(path, total, "%s%s%s", dir, need_sep ? "/" : "", file);
    return path;
}

static char *read_file_to_string(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long len = ftell(f);
    if (len < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)len, f);
    fclose(f);
    if (n != (size_t)len) { free(buf); return NULL; }
    buf[len] = '\0';
    return buf;
}

static int write_file_atomic(const char *path, const char *data) {
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    size_t len = strlen(data);
    if (fwrite(data, 1, len, f) != len) { fclose(f); unlink(tmp); return -1; }
    if (fclose(f) != 0) { unlink(tmp); return -1; }
    chmod(tmp, 0600);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static char *json_string_field(cJSON *root, const char *key) {
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (cJSON_IsString(item) && item->valuestring && item->valuestring[0]) {
        return strdup(item->valuestring);
    }
    return NULL;
}

static portillia_relay_identity *identity_from_json(cJSON *root) {
    portillia_relay_identity *id = calloc(1, sizeof(*id));
    if (!id) return NULL;

    id->name = json_string_field(root, "name");
    id->address = json_string_field(root, "address");
    id->public_key = json_string_field(root, "public_key");
    id->private_key = json_string_field(root, "private_key");
    id->token_secret = json_string_field(root, "token_secret");
    id->wireguard_public_key = json_string_field(root, "wireguard_public_key");
    id->wireguard_private_key = json_string_field(root, "wireguard_private_key");
    id->encrypted_client_hello_seed = json_string_field(root, "encrypted_client_hello_seed");

    return id;
}

bool portillia_relay_identity_is_complete(const portillia_relay_identity *identity) {
    if (!identity) return false;
    return identity->name && identity->name[0] &&
           identity->address && identity->address[0] &&
           identity->public_key && identity->public_key[0] &&
           identity->private_key && identity->private_key[0] &&
           identity->token_secret && identity->token_secret[0] &&
           identity->wireguard_public_key && identity->wireguard_public_key[0] &&
           identity->wireguard_private_key && identity->wireguard_private_key[0];
}

static portillia_relay_identity *generate_identity(const char *name) {
    char *json = GenerateRelayIdentityJSON(name);
    if (!json) {
        LOG_ERROR("GenerateRelayIdentityJSON failed for name=%s", name ? name : "");
        return NULL;
    }

    cJSON *root = cJSON_Parse(json);
    FreeCString(json);
    if (!root) {
        LOG_ERROR("failed to parse generated relay identity JSON");
        return NULL;
    }

    portillia_relay_identity *id = identity_from_json(root);
    cJSON_Delete(root);
    return id;
}

portillia_relay_identity *portillia_relay_identity_load_or_create(const char *identity_path, const char *name) {
    if (!identity_path || !identity_path[0]) return NULL;

    char *path = join_path(identity_path, "identity.json");
    if (!path) return NULL;

    portillia_relay_identity *id = NULL;
    char *data = read_file_to_string(path);
    if (data) {
        cJSON *root = cJSON_Parse(data);
        if (root) {
            id = identity_from_json(root);
            cJSON_Delete(root);
            if (id && !id->name && name && name[0]) {
                id->name = strdup(name);
            }
        }
        free(data);
    }

    if (!id || !portillia_relay_identity_is_complete(id)) {
        if (id) portillia_relay_identity_free(id);

        LOG_INFO("identity.json missing or incomplete at %s, generating new relay identity", path);
        id = generate_identity(name && name[0] ? name : "relay");
        if (!id) {
            free(path);
            return NULL;
        }

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "name", id->name ? id->name : "");
        cJSON_AddStringToObject(root, "address", id->address ? id->address : "");
        cJSON_AddStringToObject(root, "public_key", id->public_key ? id->public_key : "");
        cJSON_AddStringToObject(root, "private_key", id->private_key ? id->private_key : "");
        cJSON_AddStringToObject(root, "token_secret", id->token_secret ? id->token_secret : "");
        cJSON_AddStringToObject(root, "wireguard_public_key", id->wireguard_public_key ? id->wireguard_public_key : "");
        cJSON_AddStringToObject(root, "wireguard_private_key", id->wireguard_private_key ? id->wireguard_private_key : "");
        cJSON_AddStringToObject(root, "encrypted_client_hello_seed", id->encrypted_client_hello_seed ? id->encrypted_client_hello_seed : "");
        char *out = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);

        if (out) {
            mkdir(identity_path, 0700);
            if (write_file_atomic(path, out) != 0) {
                LOG_ERROR("failed to write identity.json to %s", path);
            } else {
                LOG_INFO("wrote new relay identity to %s address=%s", path, id->address ? id->address : "");
            }
            free(out);
        }
    }

    free(path);
    return id;
}

void portillia_relay_identity_free(portillia_relay_identity *identity) {
    if (!identity) return;
    free(identity->name);
    free(identity->address);
    free(identity->public_key);
    free(identity->private_key);
    free(identity->token_secret);
    free(identity->wireguard_public_key);
    free(identity->wireguard_private_key);
    free(identity->encrypted_client_hello_seed);
    free(identity);
}
