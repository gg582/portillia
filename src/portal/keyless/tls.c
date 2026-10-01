#include <portillia/portal/keyless/tls.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <time.h>

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    char **buf = (char **)userp;
    size_t old_len = *buf ? strlen(*buf) : 0;
    char *next = realloc(*buf, old_len + total + 1);
    if (!next) return 0;
    memcpy(next + old_len, contents, total);
    next[old_len + total] = '\0';
    *buf = next;
    return total;
}

static char *fetch_cert_chain(const char *endpoint,
                              const char *server_name,
                              bool insecure_skip_verify) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    char url[2048];
    snprintf(url, sizeof(url), "%s/.well-known/keyless-tls/cert?server_name=%s", endpoint, server_name);
    char *buf = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    portillia_network_configure_curl_tls(curl, insecure_skip_verify);
    long status = 0;
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || status >= 400) {
        LOG_WARN("Keyless TLS: fetch cert chain failed rc=%d status=%ld server=%s", rc, status, server_name);
        free(buf);
        return NULL;
    }
    return buf;
}

/* ---------- Remote signer RSA_METHOD ---------- */

typedef struct {
    char *endpoint;
    char *server_name;
    char *access_token;
    bool insecure_skip_verify;
} remote_signer_ctx_t;

static int remote_signer_ex_index = -1;

static char *base64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;
    int n = EVP_EncodeBlock((uint8_t *)out, data, (int)len);
    if (n < 0) { free(out); return NULL; }
    out[n] = '\0';
    return out;
}

static int base64_decode(const char *in, uint8_t *out, size_t out_max) {
    if (!in) return -1;
    int n = EVP_DecodeBlock(out, (const uint8_t *)in, (int)strlen(in));
    if (n < 0 || (size_t)n > out_max) return -1;
    /* EVP_DecodeBlock ignores padding; trim it. */
    size_t in_len = strlen(in);
    while (in_len > 0 && in[in_len - 1] == '=') {
        in_len--;
        n--;
    }
    return n < 0 ? -1 : n;
}

static const char *algorithm_for_nid(int nid) {
    switch (nid) {
    case NID_sha384: return "RSA_PKCS1V15_SHA384";
    case NID_sha512: return "RSA_PKCS1V15_SHA512";
    case NID_sha256:
    default: return "RSA_PKCS1V15_SHA256";
    }
}

static void remote_signer_ctx_free(remote_signer_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx->endpoint);
    free(ctx->server_name);
    free(ctx->access_token);
    free(ctx);
}

static remote_signer_ctx_t *remote_signer_ctx_new(const char *endpoint,
                                                  const char *server_name,
                                                  const char *access_token,
                                                  bool insecure_skip_verify) {
    if (!endpoint) return NULL;
    remote_signer_ctx_t *ctx = calloc(1, sizeof(remote_signer_ctx_t));
    if (!ctx) return NULL;
    ctx->endpoint = strdup(endpoint);
    ctx->server_name = server_name ? strdup(server_name) : NULL;
    ctx->access_token = access_token ? strdup(access_token) : NULL;
    ctx->insecure_skip_verify = insecure_skip_verify;
    return ctx;
}

/* BoringSSL dispatches private-key signing through RSA_METHOD. The TLS 1.2
 * path calls meth->sign with the raw digest and hash NID, which maps directly
 * onto the keyless /v1/sign digest+algorithm API. */
static int remote_rsa_sign(int type, const uint8_t *m, unsigned int m_length,
                           uint8_t *sigret, unsigned int *siglen, const RSA *rsa) {
    RSA *rsa_mut = (RSA *)rsa;
    if (type == NID_undef) {
        /* Raw sign without a digest identifier is not servable remotely. */
        LOG_WARN("Keyless TLS: remote signer received sign without hash NID; rejecting");
        return 0;
    }
    remote_signer_ctx_t *rs = (remote_signer_ctx_t *)RSA_get_ex_data(rsa_mut, remote_signer_ex_index);
    if (!rs || !rs->endpoint) {
        LOG_ERROR("Keyless TLS: missing remote signer context");
        return 0;
    }

    char *digest_b64 = base64_encode(m, (size_t)m_length);
    if (!digest_b64) return 0;

    char nonce[33] = {0};
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        uint8_t b = 0;
        RAND_bytes(&b, 1);
        nonce[i * 2] = hex[b >> 4];
        nonce[i * 2 + 1] = hex[b & 0x0f];
    }

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "key_id", "relay");
    cJSON_AddStringToObject(req, "algorithm", algorithm_for_nid(type));
    cJSON_AddStringToObject(req, "digest", digest_b64);
    cJSON_AddNumberToObject(req, "timestamp_unix", (double)time(NULL));
    cJSON_AddStringToObject(req, "nonce", nonce);
    if (rs->server_name) {
        cJSON_AddStringToObject(req, "server_name", rs->server_name);
    }
    char *req_json = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    free(digest_b64);
    if (!req_json) return 0;

    char url[2048];
    snprintf(url, sizeof(url), "%s/v1/sign", rs->endpoint);

    CURL *curl = curl_easy_init();
    if (!curl) { free(req_json); return 0; }
    char *resp = NULL;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (rs->access_token && rs->access_token[0]) {
        char auth_hdr[512];
        snprintf(auth_hdr, sizeof(auth_hdr), "X-Portal-Access-Token: %s", rs->access_token);
        headers = curl_slist_append(headers, auth_hdr);
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    portillia_network_configure_curl_tls(curl, rs->insecure_skip_verify);

    long status = 0;
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(req_json);

    if (rc != CURLE_OK || status >= 400 || !resp) {
        LOG_WARN("Keyless TLS: remote sign failed rc=%d status=%ld", rc, status);
        free(resp);
        return 0;
    }

    cJSON *resp_json = cJSON_Parse(resp);
    free(resp);
    if (!resp_json) return 0;

    int ok = 0;
    cJSON *sig_b64 = cJSON_GetObjectItem(resp_json, "signature");
    if (cJSON_IsString(sig_b64)) {
        size_t key_size = (size_t)RSA_size(rsa_mut);
        if (key_size == 0) key_size = 4096; /* fallback for dummy key */
        uint8_t *sig = malloc(key_size);
        if (sig) {
            int decoded = base64_decode(sig_b64->valuestring, sig, key_size);
            if (decoded > 0) {
                memcpy(sigret, sig, decoded);
                *siglen = (unsigned)decoded;
                ok = 1;
            }
            free(sig);
        }
    }
    cJSON_Delete(resp_json);
    return ok;
}

static int remote_rsa_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                              const uint8_t *in, size_t in_len, int padding) {
    /* RSA decryption is only used for static-RSA TLS 1.0/1.1 key exchange, which
     * we do not support.  Fail closed so the handshake fails with a clean alert. */
    (void)rsa; (void)out_len; (void)out; (void)max_out; (void)in; (void)in_len; (void)padding;
    LOG_WARN("Keyless TLS: decrypt not supported for remote signer");
    return 0;
}

/* Static method: BoringSSL references it for the lifetime of any RSA that
 * uses it (is_static=1 keeps METHOD_ref/unref from freeing it). */
static RSA_METHOD g_remote_rsa_method = {
    .common = {0, 1},
    .app_data = NULL,
    .init = NULL,
    .finish = NULL,
    .sign = remote_rsa_sign,
    .sign_raw = NULL,
    .decrypt = remote_rsa_decrypt,
    .private_transform = NULL,
    .flags = 0,
};

static void remote_signer_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                  int idx, long argl, void *argp) {
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    remote_signer_ctx_free((remote_signer_ctx_t *)ptr);
}

static void ensure_ex_index(void) {
    if (remote_signer_ex_index < 0) {
        remote_signer_ex_index = RSA_get_ex_new_index(0, NULL, NULL, NULL, remote_signer_ex_free);
    }
}

/* ---------- Public API ---------- */

/**
 * @brief Build a server-side TLS context for the leased hostname.
 *
 * Implements full remote signing via OpenSSL RSA_METHOD.  Negotiation is
 * pinned to TLS 1.2 because the remote signer cannot service the raw RSA
 * priv_enc invocations TLS 1.3 issues for PSS signatures.
 */
void *portillia_keyless_build_tls_ctx(const char *keyless_url,
                                      const char *hostname,
                                      const char *access_token,
                                      bool insecure_skip_verify) {
    if (!keyless_url) return NULL;

    ensure_ex_index();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;

    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY |
                          SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    /* TLS 1.3 issues raw RSA priv_enc with NO_PADDING for PSS, which the
     * remote signer cannot service.  Pin to TLS 1.2 and PKCS#1 v1.5 sigalgs
     * so the remote-signing path always sees pre-hashed digests with proper
     * padding. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION |
                             SSL_OP_NO_RENEGOTIATION |
                             SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-CHACHA20-POLY1305");
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
    SSL_CTX_set1_sigalgs_list(ctx,
        "RSA+SHA256:RSA+SHA384:RSA+SHA512");
    /* No ALPN: leave selection to the underlying target; browsers default
     * to HTTP/1.1 when no ALPN is offered, which is what the tunnel expects. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    char *cert_pem = fetch_cert_chain(keyless_url, hostname, insecure_skip_verify);
    X509 *leaf = NULL;
    if (cert_pem) {
        BIO *bio = BIO_new_mem_buf(cert_pem, -1);
        if (bio) {
            leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            if (leaf) {
                if (SSL_CTX_use_certificate(ctx, leaf) <= 0) {
                    LOG_ERROR("Keyless TLS: SSL_CTX_use_certificate failed");
                }
                while (1) {
                    X509 *ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
                    if (!ca) break;
                    SSL_CTX_add_extra_chain_cert(ctx, ca);
                }
            }
            BIO_free(bio);
        }
        free(cert_pem);
    }
    if (!leaf) {
        LOG_ERROR("Keyless TLS: missing leaf certificate for %s", hostname ? hostname : "(none)");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Build an RSA key whose modulus matches the cert's public key, so that
     * RSA_size and OpenSSL's TLS 1.2 signature length calculations are
     * correct.  Private operations are forwarded to the keyless endpoint. */
    EVP_PKEY *cert_pubkey = X509_get_pubkey(leaf);
    if (!cert_pubkey || EVP_PKEY_base_id(cert_pubkey) != EVP_PKEY_RSA) {
        LOG_ERROR("Keyless TLS: certificate public key is not RSA; remote signer requires RSA");
        if (cert_pubkey) EVP_PKEY_free(cert_pubkey);
        X509_free(leaf);
        SSL_CTX_free(ctx);
        return NULL;
    }

    RSA *cert_rsa = EVP_PKEY_get1_RSA(cert_pubkey);
    EVP_PKEY_free(cert_pubkey);
    X509_free(leaf);
    if (!cert_rsa) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    const BIGNUM *cert_n = NULL, *cert_e = NULL;
    RSA_get0_key(cert_rsa, &cert_n, &cert_e, NULL);

    ENGINE *engine = ENGINE_new();
    if (!engine || ENGINE_set_RSA_method(engine, &g_remote_rsa_method, sizeof(g_remote_rsa_method)) != 1) {
        if (engine) ENGINE_free(engine);
        RSA_free(cert_rsa);
        SSL_CTX_free(ctx);
        return NULL;
    }
    RSA *rsa = RSA_new_method(engine);
    ENGINE_free(engine);
    if (!rsa) {
        RSA_free(cert_rsa);
        SSL_CTX_free(ctx);
        return NULL;
    }
    BIGNUM *n = BN_dup(cert_n);
    BIGNUM *e = BN_dup(cert_e);
    if (!n || !e) {
        BN_free(n); BN_free(e);
        RSA_free(rsa);
        RSA_free(cert_rsa);
        SSL_CTX_free(ctx);
        return NULL;
    }
    RSA_set0_key(rsa, n, e, NULL);
    RSA_free(cert_rsa);

    remote_signer_ctx_t *rsctx = remote_signer_ctx_new(keyless_url, hostname, access_token, insecure_skip_verify);
    if (!rsctx) {
        RSA_free(rsa);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (RSA_set_ex_data(rsa, remote_signer_ex_index, rsctx) != 1) {
        remote_signer_ctx_free(rsctx);
        RSA_free(rsa);
        SSL_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        if (pkey) EVP_PKEY_free(pkey);
        else RSA_free(rsa);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        LOG_ERROR("Keyless TLS: SSL_CTX_use_PrivateKey failed");
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_free(pkey);

    if (!SSL_CTX_check_private_key(ctx)) {
        unsigned long e2 = ERR_get_error();
        char buf[256];
        ERR_error_string_n(e2, buf, sizeof(buf));
        LOG_DEBUG("Keyless TLS: SSL_CTX_check_private_key (expected with remote signer) err=%s", buf);
    }

    return ctx;
}

void portillia_tls_setup(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}
