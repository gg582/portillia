#include <portillia/portal/keyless/ech.h>
#include <portillia/utils/crypto.h>
#include <portillia/utils/log.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int hex_to_bytes32(const char *hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned int v = 0;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int write_uint16(uint8_t *buf, size_t *off, size_t max, uint16_t val) {
    if (*off + 2 > max) return -1;
    buf[(*off)++] = (uint8_t)((val >> 8) & 0xff);
    buf[(*off)++] = (uint8_t)(val & 0xff);
    return 0;
}

static int write_bytes_with_len(uint8_t *buf, size_t *off, size_t max, const uint8_t *data, uint16_t len) {
    if (write_uint16(buf, off, max, len) != 0) return -1;
    if (*off + len > max) return -1;
    memcpy(buf + *off, data, len);
    *off += len;
    return 0;
}

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

int portillia_keyless_ech_generate_keys(const char *siwe_private_key, const char *seed, const char *public_name, const char *out_pem_path) {
    if (!siwe_private_key || !seed || !public_name || !out_pem_path) return -1;
    if (strlen(siwe_private_key) != 64) return -1;
    if (strlen(seed) == 0) return -1;
    if (strlen(public_name) > 255) return -1;

    // Go parity: IKM = seed, salt = nil
    uint8_t x25519_priv[32];
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;
    if (EVP_PKEY_derive_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return -1; }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) { EVP_PKEY_CTX_free(pctx); return -1; }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, (const uint8_t *)seed, (int)strlen(seed)) <= 0) { EVP_PKEY_CTX_free(pctx); return -1; }
    const char *info_prefix = "portal relay ech v1:";
    size_t info_len = strlen(info_prefix) + strlen(public_name);
    uint8_t *info = malloc(info_len);
    if (!info) { EVP_PKEY_CTX_free(pctx); return -1; }
    memcpy(info, info_prefix, strlen(info_prefix));
    memcpy(info + strlen(info_prefix), public_name, strlen(public_name));
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) {
        free(info); EVP_PKEY_CTX_free(pctx); return -1;
    }
    free(info);
    size_t okm_len = 32;
    if (EVP_PKEY_derive(pctx, x25519_priv, &okm_len) <= 0) {
        EVP_PKEY_CTX_free(pctx); return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    // Create X25519 key pair
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
    if (!kctx) return -1;
    if (EVP_PKEY_fromdata_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); return -1; }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string("priv", x25519_priv, 32);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return -1;
    }
    EVP_PKEY_CTX_free(kctx);

    // Get public key
    size_t pub_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    uint8_t *pub_key = malloc(pub_len);
    if (!pub_key) { EVP_PKEY_free(pkey); return -1; }
    if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &pub_len) <= 0) {
        free(pub_key); EVP_PKEY_free(pkey);
        return -1;
    }

    // Config ID = SHA256("portal relay ech config id v1" || 0x00 || public_name || 0x00 || public_key)[0]
    uint8_t config_id_hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { free(pub_key); EVP_PKEY_free(pkey); return -1; }
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, "portal relay ech config id v1", strlen("portal relay ech config id v1"));
    uint8_t zero = 0;
    EVP_DigestUpdate(mdctx, &zero, 1);
    EVP_DigestUpdate(mdctx, public_name, strlen(public_name));
    EVP_DigestUpdate(mdctx, &zero, 1);
    EVP_DigestUpdate(mdctx, pub_key, pub_len);
    EVP_DigestFinal_ex(mdctx, config_id_hash, NULL);
    EVP_MD_CTX_free(mdctx);
    uint8_t config_id = config_id_hash[0];

    // Build ECHConfig
    uint8_t body[512];
    size_t body_off = 0;
    body[body_off++] = config_id;
    // kem_id = 0x0020 (X25519)
    if (write_uint16(body, &body_off, sizeof(body), 0x0020) != 0) goto fail;
    // public_key
    if (write_bytes_with_len(body, &body_off, sizeof(body), pub_key, (uint16_t)pub_len) != 0) goto fail;
    // cipher suites: kdf=0x0001, aead=0x0001
    uint8_t cs[4] = {0x00, 0x01, 0x00, 0x01};
    if (write_bytes_with_len(body, &body_off, sizeof(body), cs, 4) != 0) goto fail;
    // maximum_name_length
    body[body_off++] = 0xff;
    // public_name
    body[body_off++] = (uint8_t)strlen(public_name);
    memcpy(body + body_off, public_name, strlen(public_name));
    body_off += strlen(public_name);
    // extensions_len = 0
    if (write_uint16(body, &body_off, sizeof(body), 0) != 0) goto fail;

    // ECHConfig = version(2) + length(2) + body
    uint8_t ech_config[1024];
    size_t ech_off = 0;
    if (write_uint16(ech_config, &ech_off, sizeof(ech_config), 0xfe0d) != 0) goto fail;
    if (write_uint16(ech_config, &ech_off, sizeof(ech_config), (uint16_t)body_off) != 0) goto fail;
    if (ech_off + body_off > sizeof(ech_config)) goto fail;
    memcpy(ech_config + ech_off, body, body_off);
    ech_off += body_off;

    // ECHConfigList = length(2) + ECHConfig
    uint8_t ech_list[1024];
    size_t list_off = 0;
    if (write_uint16(ech_list, &list_off, sizeof(ech_list), (uint16_t)ech_off) != 0) goto fail;
    if (list_off + ech_off > sizeof(ech_list)) goto fail;
    memcpy(ech_list + list_off, ech_config, ech_off);
    list_off += ech_off;

    // PKCS#8 private key PEM
    BIO *pk_bio = BIO_new(BIO_s_mem());
    if (!pk_bio) goto fail;
    if (!PEM_write_bio_PKCS8PrivateKey(pk_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free_all(pk_bio);
        goto fail;
    }
    BUF_MEM *pk_buf;
    BIO_get_mem_ptr(pk_bio, &pk_buf);

    // ECHCONFIG PEM
    char *ech_b64 = base64_encode(ech_list, list_off);
    if (!ech_b64) { BIO_free_all(pk_bio); goto fail; }

    FILE *fp = fopen(out_pem_path, "w");
    if (!fp) {
        free(ech_b64);
        BIO_free_all(pk_bio);
        goto fail;
    }
    fwrite(pk_buf->data, 1, pk_buf->length, fp);
    fprintf(fp, "-----BEGIN ECHCONFIG-----\n");
    // Wrap base64 to 64 chars per line
    size_t ech_len = strlen(ech_b64);
    for (size_t i = 0; i < ech_len; i += 64) {
        size_t line = (ech_len - i < 64) ? (ech_len - i) : 64;
        fwrite(ech_b64 + i, 1, line, fp);
        fputc('\n', fp);
    }
    fprintf(fp, "-----END ECHCONFIG-----\n");
    fclose(fp);

    free(ech_b64);
    BIO_free_all(pk_bio);
    free(pub_key);
    EVP_PKEY_free(pkey);
    LOG_INFO("ECH keys generated at %s", out_pem_path);
    return 0;

fail:
    free(pub_key);
    EVP_PKEY_free(pkey);
    return -1;
}
