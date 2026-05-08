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
    bool insecure_skip_verify;
} remote_signer_ctx_t;

static int remote_signer_ex_index = -1;

static char *base64_encode(const uint8_t *data, size_t len) {
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
    }
    BIO_free_all(bio);
    return out;
}

static int base64_decode(const char *in, uint8_t *out, size_t out_max) {
    BIO *bio = BIO_new_mem_buf(in, (int)strlen(in));
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded = BIO_read(bio, out, (int)out_max);
    BIO_free_all(bio);
    return decoded;
}

static const char *detect_algorithm(int flen, int padding) {
    if (padding == RSA_PKCS1_PSS_PADDING) {
        if (flen == 48) return "RSAPSSSHA384";
        if (flen == 64) return "RSAPSSSHA512";
        return "RSAPSSSHA256";
    }
    if (flen == 48) return "RSAPKCS1v15SHA384";
    if (flen == 64) return "RSAPKCS1v15SHA512";
    return "RSAPKCS1v15SHA256";
}

static void remote_signer_ctx_free(remote_signer_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx->endpoint);
    free(ctx->server_name);
    free(ctx);
}

static remote_signer_ctx_t *remote_signer_ctx_new(const char *endpoint,
                                                  const char *server_name,
                                                  bool insecure_skip_verify) {
    if (!endpoint) return NULL;
    remote_signer_ctx_t *ctx = calloc(1, sizeof(remote_signer_ctx_t));
    if (!ctx) return NULL;
    ctx->endpoint = strdup(endpoint);
    ctx->server_name = server_name ? strdup(server_name) : NULL;
    ctx->insecure_skip_verify = insecure_skip_verify;
    return ctx;
}

static int remote_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    if (padding == RSA_NO_PADDING) {
        /* TLS 1.3 PSS path supplies pre-encoded PSS messages with NO_PADDING.
         * Our remote signer takes digests + algorithm name, not raw blocks,
         * so we cannot service this; force the caller to negotiate TLS 1.2. */
        LOG_WARN("Keyless TLS: remote signer received RSA_NO_PADDING (TLS 1.3 PSS) request; rejecting");
        return -1;
    }
    remote_signer_ctx_t *rs = (remote_signer_ctx_t *)RSA_get_ex_data(rsa, remote_signer_ex_index);
    if (!rs || !rs->endpoint) {
        LOG_ERROR("Keyless TLS: missing remote signer context");
        return -1;
    }

    char *digest_b64 = base64_encode(from, (size_t)flen);
    if (!digest_b64) return -1;

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
    cJSON_AddStringToObject(req, "algorithm", detect_algorithm(flen, padding));
    cJSON_AddStringToObject(req, "digest", digest_b64);
    cJSON_AddNumberToObject(req, "timestamp_unix", (double)time(NULL));
    cJSON_AddStringToObject(req, "nonce", nonce);
    if (rs->server_name) {
        cJSON_AddStringToObject(req, "server_name", rs->server_name);
    }
    char *req_json = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    free(digest_b64);
    if (!req_json) return -1;

    char url[2048];
    snprintf(url, sizeof(url), "%s/v1/sign", rs->endpoint);

    CURL *curl = curl_easy_init();
    if (!curl) { free(req_json); return -1; }
    char *resp = NULL;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
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
        return -1;
    }

    cJSON *resp_json = cJSON_Parse(resp);
    free(resp);
    if (!resp_json) return -1;

    int sig_len = 0;
    cJSON *sig_b64 = cJSON_GetObjectItem(resp_json, "signature");
    if (cJSON_IsString(sig_b64)) {
        size_t key_size = (size_t)RSA_size(rsa);
        if (key_size == 0) key_size = 4096; /* fallback for dummy key */
        uint8_t *sig = malloc(key_size);
        if (sig) {
            int decoded = base64_decode(sig_b64->valuestring, sig, key_size);
            if (decoded > 0) {
                memcpy(to, sig, decoded);
                sig_len = decoded;
            }
            free(sig);
        }
    }
    cJSON_Delete(resp_json);
    return sig_len;
}

static int remote_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    /* RSA decryption is only used for static-RSA TLS 1.0/1.1 key exchange, which
     * we do not support.  Fail closed so the handshake fails with a clean alert. */
    (void)flen; (void)from; (void)to; (void)rsa; (void)padding;
    LOG_WARN("Keyless TLS: priv_dec not supported for remote signer");
    return -1;
}

static RSA_METHOD *get_remote_rsa_method(void) {
    static RSA_METHOD *method = NULL;
    if (method) return method;
    method = RSA_meth_dup(RSA_get_default_method());
    if (!method) return NULL;
    RSA_meth_set1_name(method, "Portillia Remote RSA Signer");
    RSA_meth_set_flags(method, 0);
    RSA_meth_set_priv_enc(method, remote_rsa_priv_enc);
    RSA_meth_set_priv_dec(method, remote_rsa_priv_dec);
    return method;
}

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

    RSA_METHOD *method = get_remote_rsa_method();
    if (!method) {
        RSA_free(cert_rsa);
        SSL_CTX_free(ctx);
        return NULL;
    }
    RSA *rsa = RSA_new();
    if (!rsa) {
        RSA_free(cert_rsa);
        SSL_CTX_free(ctx);
        return NULL;
    }
    RSA_set_method(rsa, method);
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

    remote_signer_ctx_t *rsctx = remote_signer_ctx_new(keyless_url, hostname, insecure_skip_verify);
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
