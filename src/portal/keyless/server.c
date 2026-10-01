#include <portillia/portal/keyless/server.h>
#include <portillia/portal/keyless/bindings.h>
#include <portillia/portal/identity.h>
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
    portillia_relay_identity *identity = portillia_relay_identity_load_or_create(identity_path, NULL);
    if (!identity) return -1;

    if (g_private_key_hex) { free(g_private_key_hex); g_private_key_hex = NULL; }
    if (g_public_key_hex) { free(g_public_key_hex); g_public_key_hex = NULL; }

    if (identity->private_key && identity->private_key[0]) {
        g_private_key_hex = strdup(identity->private_key);
    }
    if (identity->public_key && identity->public_key[0]) {
        g_public_key_hex = strdup(identity->public_key);
    }

    int ok = (g_private_key_hex && g_public_key_hex) ? 0 : -1;
    portillia_relay_identity_free(identity);
    return ok;
}

static char *base64_decode(const char *in, size_t *out_len) {
    size_t max_len = (strlen(in) / 4 + 1) * 3;
    char *buf = malloc(max_len + 1);
    if (!buf) return NULL;
    int n = EVP_DecodeBlock((uint8_t *)buf, (const uint8_t *)in, (int)strlen(in));
    if (n < 0) { free(buf); return NULL; }
    size_t in_len = strlen(in);
    while (in_len > 0 && in[in_len - 1] == '=') { in_len--; n--; }
    *out_len = (size_t)n;
    return buf;
}

static char *base64_encode(const uint8_t *in, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;
    int n = EVP_EncodeBlock((uint8_t *)out, in, (int)len);
    if (n < 0) { free(out); return NULL; }
    out[n] = '\0';
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

/* relayKeyID is the store key of the relay API listener certificate key.
 * Tenant handshakes address it explicitly in every TranscriptSignRequest
 * (portal-tunnel portal/keyless/signer.go). */
#define PORTILLIA_RELAY_KEY_ID "relay-cert"
/* Bounds matching signer.go: transcript bodies carry certificate chains. */
#define PORTILLIA_SIGN_MAX_BODY (512 << 10)
#define PORTILLIA_SIGN_ALLOWED_SKEW_SEC 30

/* Decodes a JSON []byte field (standard base64, per Go encoding/json). */
static int json_b64_field(const cJSON *root, const char *name, uint8_t **out, size_t *out_len) {
    cJSON *item = cJSON_GetObjectItem((cJSON *)root, name);
    if (!cJSON_IsString(item) || !item->valuestring || !item->valuestring[0]) return -1;
    size_t len = 0;
    char *decoded = base64_decode(item->valuestring, &len);
    if (!decoded || len == 0) { free(decoded); return -1; }
    *out = (uint8_t *)decoded;
    *out_len = len;
    return 0;
}

/* Signs the TLS 1.3 CertificateVerify content (RFC 8446 §4.4.3) with the
 * relay certificate key, mirroring signer.Service.SignTranscript: the digest
 * fed to the signing key is SHA-256(content) for ECDSA_SHA256 and
 * RSA_PSS_SHA256 (PSS salt length = hash length), and the raw content for
 * Ed25519. */
static int sign_certificate_verify(const char *algorithm,
                                   const uint8_t *content, size_t content_len,
                                   uint8_t **sig_out, size_t *sig_len) {
    const EVP_MD *md = NULL;
    int pss = 0;
    if (strcmp(algorithm, "ECDSA_SHA256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(algorithm, "RSA_PSS_SHA256") == 0) {
        md = EVP_sha256();
        pss = 1;
    } else if (strcmp(algorithm, "Ed25519") == 0) {
        md = NULL;
    } else {
        LOG_ERROR("Keyless server: unsupported algorithm %s", algorithm);
        return -2;
    }

    EVP_PKEY *pkey = load_acme_private_key();
    if (!pkey) {
        LOG_ERROR("Keyless server: failed to load ACME private key");
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_CTX *pctx = NULL;
    int rc = -1;

    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey) != 1) goto done;
    if (pss) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) goto done;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1) goto done;
        if (EVP_PKEY_CTX_set_signature_md(pctx, md) != 1) goto done;
    }
    if (EVP_DigestSignUpdate(ctx, content, content_len) != 1) goto done;

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

/* Verifies the access token and returns the caller's identity address
 * (claims.identity_address), which is the lease identity the relay binds
 * transcripts to. Caller frees. */
static char *verify_access_token_address(const char *token) {
    if (!token || !token[0] || !g_public_key_hex) return NULL;
    char *claims_json = VerifyLeaseTokenJSON(token, g_public_key_hex, "portal-sdk", (long long)time(NULL));
    if (!claims_json) return NULL;
    char *address = NULL;
    cJSON *claims = cJSON_Parse(claims_json);
    if (claims) {
        cJSON *addr = cJSON_GetObjectItem(claims, "identity_address");
        if (cJSON_IsString(addr) && addr->valuestring && addr->valuestring[0]) {
            address = strdup(addr->valuestring);
        }
        cJSON_Delete(claims);
    }
    FreeRustString(claims_json);
    return address;
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

static void write_sign_error(cwist_http_response *res, int status, const char *message) {
    char body[512];
    snprintf(body, sizeof(body), "{\"error\":\"%s\"}", message);
    res->status_code = status;
    cwist_sstring_assign(res->body, body);
    cwist_http_header_add(&res->headers, "Content-Type", "application/json");
}

/* Transcript-bound transcript signer (portal-tunnel portal/keyless/signer.go
 * + keyless_tls relay/signer.Service): the request carries the TLS 1.3
 * handshake transcript and the relay-minted connection binding; the response
 * is the CertificateVerify signature. Errors map like signer.go: invalid
 * argument -> 400, permission denied (token, lease, binding, key) -> 403,
 * anything else -> 500. */
static void handle_keyless_sign(cwist_http_request *req, cwist_http_response *res) {
    if (req->method != CWIST_HTTP_POST) {
        cwist_http_header_add(&res->headers, "Allow", "POST");
        write_sign_error(res, 405, "method not allowed");
        return;
    }

    const char *ct = cwist_http_header_get(req->headers, "Content-Type");
    if (ct && ct[0] && strncmp(ct, "application/json", 16) != 0) {
        write_sign_error(res, CWIST_HTTP_UNSUPPORTED_MEDIA_TYPE, "content type must be application/json");
        return;
    }

    if (!req->body || req->body->size == 0 || req->body->size > PORTILLIA_SIGN_MAX_BODY) {
        write_sign_error(res, CWIST_HTTP_BAD_REQUEST, "invalid json body");
        return;
    }

    cJSON *root = cJSON_Parse(req->body->data);
    if (!root) {
        write_sign_error(res, CWIST_HTTP_BAD_REQUEST, "invalid json body");
        return;
    }

    cJSON *key_id_obj = cJSON_GetObjectItem(root, "key_id");
    cJSON *alg_obj = cJSON_GetObjectItem(root, "algorithm");
    cJSON *nonce_obj = cJSON_GetObjectItem(root, "nonce");
    if (!cJSON_IsString(key_id_obj) || !key_id_obj->valuestring || !key_id_obj->valuestring[0] ||
        !cJSON_IsString(alg_obj) || !alg_obj->valuestring || !alg_obj->valuestring[0] ||
        !cJSON_IsString(nonce_obj) || !nonce_obj->valuestring || !nonce_obj->valuestring[0]) {
        cJSON_Delete(root);
        write_sign_error(res, CWIST_HTTP_BAD_REQUEST, "invalid argument: missing required metadata field");
        return;
    }

    uint8_t *binding = NULL, *client_hello = NULL, *server_hello = NULL, *encrypted_extensions = NULL, *certificate = NULL;
    size_t binding_len = 0, client_hello_len = 0, server_hello_len = 0, ee_len = 0, cert_len = 0;
    if (json_b64_field(root, "binding", &binding, &binding_len) != 0 ||
        json_b64_field(root, "client_hello", &client_hello, &client_hello_len) != 0 ||
        json_b64_field(root, "server_hello", &server_hello, &server_hello_len) != 0 ||
        json_b64_field(root, "encrypted_extensions", &encrypted_extensions, &ee_len) != 0 ||
        json_b64_field(root, "certificate", &certificate, &cert_len) != 0) {
        free(binding); free(client_hello); free(server_hello); free(encrypted_extensions); free(certificate);
        cJSON_Delete(root);
        write_sign_error(res, CWIST_HTTP_BAD_REQUEST, "invalid argument: missing required handshake transcript field");
        return;
    }

    cJSON *ts_obj = cJSON_GetObjectItem(root, "timestamp_unix");
    long long now = (long long)time(NULL);
    if (!cJSON_IsNumber(ts_obj) ||
        (long long)ts_obj->valuedouble < now - PORTILLIA_SIGN_ALLOWED_SKEW_SEC ||
        (long long)ts_obj->valuedouble > now + PORTILLIA_SIGN_ALLOWED_SKEW_SEC) {
        free(binding); free(client_hello); free(server_hello); free(encrypted_extensions); free(certificate);
        cJSON_Delete(root);
        write_sign_error(res, CWIST_HTTP_BAD_REQUEST, "invalid argument: request timestamp outside allowed skew");
        return;
    }

    char *token = cwist_http_header_get(req->headers, "X-Portal-Access-Token");
    char *lease_id = verify_access_token_address(token);
    if (!lease_id) {
        free(binding); free(client_hello); free(server_hello); free(encrypted_extensions); free(certificate);
        cJSON_Delete(root);
        write_sign_error(res, CWIST_HTTP_FORBIDDEN, "unauthorized");
        return;
    }

    /* TranscriptValidator (signer.go:52-58): the signature is bound to a
     * verified lease and the relay-minted, single-use binding pinned to the
     * sha256 of the relay-observed ClientHello. */
    if (lease_id[0] == '\0') {
        free(lease_id);
        free(binding); free(client_hello); free(server_hello); free(encrypted_extensions); free(certificate);
        cJSON_Delete(root);
        write_sign_error(res, CWIST_HTTP_FORBIDDEN,
                         "permission denied: signing request is not bound to a verified lease");
        return;
    }
    portillia_binding_status vstatus = portillia_bindings_validate_and_consume(
        portillia_bindings_shared(), binding, binding_len, lease_id, client_hello, client_hello_len);
    free(lease_id);
    if (vstatus != PORTILLIA_BINDING_OK) {
        char message[160];
        snprintf(message, sizeof(message), "permission denied: %s", portillia_binding_strerror(vstatus));
        free(binding); free(client_hello); free(server_hello); free(encrypted_extensions); free(certificate);
        cJSON_Delete(root);
        write_sign_error(res, CWIST_HTTP_FORBIDDEN, message);
        return;
    }

    if (strcmp(key_id_obj->valuestring, PORTILLIA_RELAY_KEY_ID) != 0) {
        free(binding); free(client_hello); free(server_hello); free(encrypted_extensions); free(certificate);
        cJSON_Delete(root);
        write_sign_error(res, CWIST_HTTP_FORBIDDEN, "permission denied: unknown signing key");
        return;
    }
    free(binding);

    /* TLS 1.3 transcript hash (RFC 8446 §4.4.1, SHA-256 per cipher suite) and
     * CertificateVerify content (§4.4.3), per signer.computeTranscriptHash /
     * FormatCertificateVerifyContent. */
    SHA256_CTX sha;
    uint8_t transcript_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha);
    SHA256_Update(&sha, client_hello, client_hello_len);
    SHA256_Update(&sha, server_hello, server_hello_len);
    SHA256_Update(&sha, encrypted_extensions, ee_len);
    SHA256_Update(&sha, certificate, cert_len);
    SHA256_Final(transcript_hash, &sha);
    free(client_hello); free(server_hello); free(encrypted_extensions); free(certificate);

    static const char cv_context[] = "TLS 1.3, server CertificateVerify";
    uint8_t content[64 + sizeof(cv_context) + SHA256_DIGEST_LENGTH];
    memset(content, 0x20, 64);
    memcpy(content + 64, cv_context, sizeof(cv_context)); /* includes trailing NUL */
    memcpy(content + 64 + sizeof(cv_context), transcript_hash, SHA256_DIGEST_LENGTH);

    /* hashContentForAlgorithm: SHA-256 of the content unless Ed25519. */
    uint8_t digest[SHA256_DIGEST_LENGTH];
    const uint8_t *sign_input = content;
    size_t sign_input_len = sizeof(content);
    if (strcmp(alg_obj->valuestring, "Ed25519") != 0) {
        SHA256(content, sizeof(content), digest);
        sign_input = digest;
        sign_input_len = sizeof(digest);
    }

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    int sign_rc = sign_certificate_verify(alg_obj->valuestring, sign_input, sign_input_len, &sig, &sig_len);
    char *alg_copy = strdup(alg_obj->valuestring);
    char *key_id_copy = strdup(key_id_obj->valuestring);
    cJSON_Delete(root);
    if (sign_rc != 0 || !sig) {
        free(alg_copy); free(key_id_copy);
        write_sign_error(res, CWIST_HTTP_INTERNAL_ERROR, "sign failed");
        return;
    }

    char *sig_b64 = base64_encode(sig, sig_len);
    free(sig);
    if (!sig_b64) {
        free(alg_copy); free(key_id_copy);
        write_sign_error(res, CWIST_HTTP_INTERNAL_ERROR, "encode failed");
        return;
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "key_id", key_id_copy);
    cJSON_AddStringToObject(resp, "algorithm", alg_copy);
    cJSON_AddStringToObject(resp, "signature", sig_b64);
    free(alg_copy); free(key_id_copy); free(sig_b64);
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
