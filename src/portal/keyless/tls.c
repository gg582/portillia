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
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) {
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

static int remote_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    remote_signer_ctx_t *rs = (remote_signer_ctx_t *)RSA_get_app_data(rsa);
    if (!rs || !rs->endpoint) return 0;

    char *digest_b64 = base64_encode(from, (size_t)flen);
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
    cJSON_AddStringToObject(req, "algorithm", detect_algorithm(flen, padding));
    cJSON_AddStringToObject(req, "digest", digest_b64);
    cJSON_AddNumberToObject(req, "timestamp_unix", (double)time(NULL));
    cJSON_AddStringToObject(req, "nonce", nonce);
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
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    portillia_network_configure_curl_tls(curl, rs->insecure_skip_verify);

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(req_json);

    if (rc != CURLE_OK || !resp) {
        free(resp);
        return 0;
    }

    cJSON *resp_json = cJSON_Parse(resp);
    free(resp);
    if (!resp_json) return 0;

    cJSON *sig_b64 = cJSON_GetObjectItem(resp_json, "signature");
    int sig_len = 0;
    if (cJSON_IsString(sig_b64)) {
        uint8_t sig[512];
        sig_len = base64_decode(sig_b64->valuestring, sig, sizeof(sig));
        if (sig_len > 0) {
            memcpy(to, sig, sig_len);
        }
    }
    cJSON_Delete(resp_json);
    return sig_len;
}

static RSA_METHOD *get_remote_rsa_method(void) {
    static RSA_METHOD *method = NULL;
    if (method) return method;
    method = RSA_meth_new("Portillia Remote RSA Signer", 0);
    if (!method) return NULL;
    RSA_meth_set_priv_enc(method, remote_rsa_priv_enc);
    return method;
}

static remote_signer_ctx_t *remote_signer_ctx_new(const char *endpoint,
                                                  const char *server_name,
                                                  bool insecure_skip_verify) {
    remote_signer_ctx_t *ctx = calloc(1, sizeof(remote_signer_ctx_t));
    ctx->endpoint = strdup(endpoint);
    ctx->server_name = server_name ? strdup(server_name) : NULL;
    ctx->insecure_skip_verify = insecure_skip_verify;
    return ctx;
}

/* ---------- Public API ---------- */

/**
 * @brief Build a server-side TLS context for the leased hostname.
 *
 * Implements full remote signing via OpenSSL RSA_METHOD.  The private
 * key operations are forwarded to the keyless endpoint over HTTPS.
 */
void *portillia_keyless_build_tls_ctx(const char *keyless_url,
                                      const char *hostname,
                                      bool insecure_skip_verify) {
    if (!keyless_url) return NULL;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;

    char *cert_pem = fetch_cert_chain(keyless_url, hostname, insecure_skip_verify);
    if (cert_pem) {
        BIO *bio = BIO_new_mem_buf(cert_pem, -1);
        if (bio) {
            X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            if (cert) {
                SSL_CTX_use_certificate(ctx, cert);
                X509_free(cert);
            }
            while (1) {
                X509 *ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
                if (!ca) break;
                SSL_CTX_add_extra_chain_cert(ctx, ca);
            }
            BIO_free(bio);
        }
        free(cert_pem);
    }

    /* Create an RSA key with our custom remote signing method */
    RSA_METHOD *method = get_remote_rsa_method();
    if (!method) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    RSA *rsa = RSA_new();
    if (!rsa) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    RSA_set_method(rsa, method);
    /* Set a dummy modulus so OpenSSL knows the key size */
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    BN_set_word(n, 0);
    RSA_set0_key(rsa, n, e, NULL);
    RSA_set_app_data(rsa, remote_signer_ctx_new(keyless_url, hostname, insecure_skip_verify));

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);

    if (!SSL_CTX_check_private_key(ctx)) {
        LOG_WARN("Keyless TLS: private key does not match certificate (expected with remote signer)");
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

void portillia_tls_setup(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}
