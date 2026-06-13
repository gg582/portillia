#include <portillia/portal/keyless/server.h>
#include <portillia/utils/log.h>
#include <cwist/sys/app/app.h>
#include <cwist/core/sstring/sstring.h>
#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include "portal_bridge.h"

static char *g_identity_path = NULL;
static char *g_private_key_hex = NULL;
static char *g_public_key_hex = NULL;

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

static int load_identity_json(const char *identity_path) {
    char *path = join_path(identity_path, "identity.json");
    if (!path) return -1;
    char *json = read_file_to_string(path);
    free(path);
    if (!json) return -1;

    cJSON *root = cJSON_Parse(json);
    free(json);
    if (!root) return -1;

    cJSON *priv = cJSON_GetObjectItem(root, "private_key");
    cJSON *pub = cJSON_GetObjectItem(root, "public_key");
    if (g_private_key_hex) { free(g_private_key_hex); g_private_key_hex = NULL; }
    if (g_public_key_hex) { free(g_public_key_hex); g_public_key_hex = NULL; }
    if (cJSON_IsString(priv) && priv->valuestring && priv->valuestring[0]) {
        g_private_key_hex = strdup(priv->valuestring);
    }
    if (cJSON_IsString(pub) && pub->valuestring && pub->valuestring[0]) {
        g_public_key_hex = strdup(pub->valuestring);
    }
    cJSON_Delete(root);
    return (g_private_key_hex && g_public_key_hex) ? 0 : -1;
}

static char *base64_decode(const char *in, size_t *out_len) {
    BIO *bio = BIO_new_mem_buf(in, (int)strlen(in));
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    size_t max_len = (strlen(in) / 4 + 1) * 3;
    char *buf = malloc(max_len);
    if (!buf) { BIO_free_all(bio); return NULL; }
    int n = BIO_read(bio, buf, (int)max_len);
    BIO_free_all(bio);
    if (n < 0) { free(buf); return NULL; }
    *out_len = (size_t)n;
    return buf;
}

static char *base64_encode(const uint8_t *in, size_t len) {
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, in, (int)len);
    BIO_flush(bio);
    BUF_MEM *buf;
    BIO_get_mem_ptr(bio, &buf);
    char *out = malloc(buf->length + 1);
    if (out) {
        memcpy(out, buf->data, buf->length);
        out[buf->length] = '\0';
    }
    BIO_free_all(bio);
    return out;
}

static EVP_PKEY *load_acme_private_key(void) {
    if (!g_identity_path) return NULL;
    char *path = join_path(g_identity_path, "privatekey.pem");
    if (!path) return NULL;
    FILE *f = fopen(path, "r");
    free(path);
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

static const EVP_MD *md_from_algorithm(const char *alg) {
    if (strstr(alg, "SHA256")) return EVP_sha256();
    if (strstr(alg, "SHA384")) return EVP_sha384();
    if (strstr(alg, "SHA512")) return EVP_sha512();
    return NULL;
}

static int is_pss(const char *alg) {
    return strstr(alg, "PSS") != NULL;
}

static int sign_with_private_key(const uint8_t *digest, size_t digest_len,
                                  const char *algorithm,
                                  uint8_t **sig_out, size_t *sig_len) {
    EVP_PKEY *pkey = load_acme_private_key();
    if (!pkey) {
        LOG_ERROR("Keyless server: failed to load ACME private key");
        return -1;
    }

    const EVP_MD *md = md_from_algorithm(algorithm);
    if (!md) {
        LOG_ERROR("Keyless server: unsupported algorithm %s", algorithm);
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_CTX *pctx = NULL;
    int rc = -1;

    if (is_pss(algorithm)) {
        if (EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey) != 1) goto done;
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) goto done;
        if (EVP_PKEY_CTX_set_signature_md(pctx, md) != 1) goto done;
    } else {
        if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) goto done;
    }

    if (EVP_DigestSignUpdate(ctx, digest, digest_len) != 1) goto done;

    size_t req_len = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &req_len) != 1) goto done;
    *sig_out = malloc(req_len);
    if (!*sig_out) goto done;
    *sig_len = req_len;
    if (EVP_DigestSignFinal(ctx, *sig_out, sig_len) != 1) {
        free(*sig_out);
        *sig_out = NULL;
        goto done;
    }
    rc = 0;

done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

static int verify_access_token(const char *token) {
    if (!token || !token[0] || !g_public_key_hex) return -1;
    char *claims = VerifyLeaseTokenJSON(token, g_public_key_hex, "portal-sdk", (long long)time(NULL));
    if (!claims) return -1;
    FreeRustString(claims);
    return 0;
}

static void handle_keyless_cert(cwist_http_request *req, cwist_http_response *res) {
    (void)req;
    if (!g_identity_path) {
        res->status_code = CWIST_HTTP_INTERNAL_ERROR;
        return;
    }
    char *path = join_path(g_identity_path, "fullchain.pem");
    if (!path) {
        res->status_code = CWIST_HTTP_INTERNAL_ERROR;
        return;
    }
    char *pem = read_file_to_string(path);
    free(path);
    if (!pem) {
        res->status_code = CWIST_HTTP_NOT_FOUND;
        return;
    }
    cwist_sstring_assign(res->body, pem);
    free(pem);
    cwist_http_header_add(&res->headers, "Content-Type", "application/x-pem-file");
}

static void handle_keyless_sign(cwist_http_request *req, cwist_http_response *res) {
    if (req->method != CWIST_HTTP_POST) {
        res->status_code = 405;
        cwist_sstring_assign(res->body, "{\"error\":\"method not allowed\"}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    char *token = cwist_http_header_get(req->headers, "X-Portal-Access-Token");
    if (!token || verify_access_token(token) != 0) {
        res->status_code = CWIST_HTTP_FORBIDDEN;
        cwist_sstring_assign(res->body, "{\"error\":\"unauthorized\"}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    if (!req->body || req->body->size == 0) {
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"error\":\"empty body\"}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    cJSON *root = cJSON_Parse(req->body->data);
    if (!root) {
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"error\":\"invalid json\"}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    cJSON *alg_obj = cJSON_GetObjectItem(root, "algorithm");
    cJSON *digest_obj = cJSON_GetObjectItem(root, "digest");
    if (!cJSON_IsString(alg_obj) || !alg_obj->valuestring ||
        !cJSON_IsString(digest_obj) || !digest_obj->valuestring) {
        cJSON_Delete(root);
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"error\":\"missing algorithm or digest\"}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    size_t digest_len = 0;
    char *digest = base64_decode(digest_obj->valuestring, &digest_len);
    if (!digest) {
        cJSON_Delete(root);
        res->status_code = CWIST_HTTP_BAD_REQUEST;
        cwist_sstring_assign(res->body, "{\"error\":\"invalid digest base64\"}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    int sign_rc = sign_with_private_key((uint8_t *)digest, digest_len, alg_obj->valuestring, &sig, &sig_len);
    free(digest);
    cJSON_Delete(root);

    if (sign_rc != 0 || !sig) {
        res->status_code = CWIST_HTTP_INTERNAL_ERROR;
        cwist_sstring_assign(res->body, "{\"error\":\"sign failed\"}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    char *sig_b64 = base64_encode(sig, sig_len);
    free(sig);
    if (!sig_b64) {
        res->status_code = CWIST_HTTP_INTERNAL_ERROR;
        cwist_sstring_assign(res->body, "{\"error\":\"encode failed\"}");
        cwist_http_header_add(&res->headers, "Content-Type", "application/json");
        return;
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "key_id", "relay");
    cJSON_AddStringToObject(resp, "algorithm", alg_obj->valuestring);
    cJSON_AddStringToObject(resp, "signature", sig_b64);
    free(sig_b64);
    char *resp_json = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    cwist_sstring_assign(res->body, resp_json);
    free(resp_json);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

char *portillia_issue_lease_token(const char *name, const char *address, int ttl_seconds) {
    if (!g_private_key_hex || !name || !address) return NULL;
    cJSON *identity = cJSON_CreateObject();
    cJSON_AddStringToObject(identity, "name", name);
    cJSON_AddStringToObject(identity, "address", address);
    char *identity_json = cJSON_PrintUnformatted(identity);
    cJSON_Delete(identity);
    if (!identity_json) return NULL;
    char *token_json = IssueLeaseTokenJSON(g_private_key_hex, "relay", "portal-sdk", identity_json, ttl_seconds);
    free(identity_json);
    return token_json;
}

char *portillia_verify_lease_token(const char *token) {
    if (!g_public_key_hex || !token) return NULL;
    return VerifyLeaseTokenJSON(token, g_public_key_hex, "portal-sdk", (long long)time(NULL));
}

void portillia_keyless_server_setup(cwist_app *app, const char *identity_path) {
    if (!app || !identity_path) return;
    if (g_identity_path) free(g_identity_path);
    g_identity_path = strdup(identity_path);
    if (load_identity_json(identity_path) != 0) {
        LOG_WARN("Keyless server: failed to load identity.json from %s", identity_path);
    } else {
        LOG_INFO("Keyless server: loaded identity keys");
    }
    cwist_app_get(app, "/.well-known/keyless-tls/cert", handle_keyless_cert);
    cwist_app_post(app, "/v1/sign", handle_keyless_sign);
}
