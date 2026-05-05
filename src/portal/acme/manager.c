#include <portillia/portal/acme/manager.h>
#include <portillia/portal/acme/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>
#include <curl/curl.h>

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

static char *fetch_public_ip(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    char *buf = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, "https://ifconfig.me/ip");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || !buf) {
        free(buf);
        return NULL;
    }
    /* Trim whitespace */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' ' || buf[len-1] == '\t')) {
        buf[--len] = '\0';
    }
    if (len == 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

static int ensure_acme_account(portillia_acme_manager *m) {
    char account_key_path[512];
    snprintf(account_key_path, sizeof(account_key_path), "%s/acme-account.key", m->cfg.key_dir);
    m->acme_account_key_path = strdup(account_key_path);
    char email[256];
    snprintf(email, sizeof(email), "acme@%s", m->cfg.base_domain ? m->cfg.base_domain : "example.com");
    m->acme_email = strdup(email);

    if (access(m->acme_account_key_path, F_OK) != 0) {
        LOG_INFO("ACME: No account key found, generating a new one...");
        // In a real scenario, use OpenSSL to generate an ECDSA key
        // For now, create a dummy file
        FILE *f = fopen(m->acme_account_key_path, "w");
        if (f) { fprintf(f, "dummy_acme_key"); fclose(f); }
        LOG_INFO("ACME: Generated dummy account key %s", m->acme_account_key_path);

        // In Go, this would register the account with the ACME server
        // and save registration data to acme-registration.json
        char registration_path[512];
        snprintf(registration_path, sizeof(registration_path), "%s/acme-registration.json", m->cfg.key_dir);
        FILE *reg_f = fopen(registration_path, "w");
        if (reg_f) { fprintf(reg_f, "{}"); fclose(reg_f); }
        LOG_INFO("ACME: Created dummy registration file %s", registration_path);
    } else {
        LOG_INFO("ACME: Using existing account key %s", m->acme_account_key_path);
    }
    return CWIST_SUCCESS;
}

portillia_acme_manager* portillia_acme_manager_new(portillia_acme_config cfg) {
    portillia_acme_manager *m = calloc(1, sizeof(portillia_acme_manager));
    m->cfg = cfg;
    
    m->cfg.base_domain = cfg.base_domain ? strdup(cfg.base_domain) : NULL;
    m->cfg.key_dir = cfg.key_dir ? strdup(cfg.key_dir) : NULL;
    m->cfg.dns_provider_type = cfg.dns_provider_type ? strdup(cfg.dns_provider_type) : NULL;
    m->cfg.ens_gasless_address = cfg.ens_gasless_address ? strdup(cfg.ens_gasless_address) : NULL;
    m->cfg.cloudflare_token = cfg.cloudflare_token ? strdup(cfg.cloudflare_token) : NULL;
    m->cfg.gcp_project_id = cfg.gcp_project_id ? strdup(cfg.gcp_project_id) : NULL;
    m->cfg.gcp_managed_zone = cfg.gcp_managed_zone ? strdup(cfg.gcp_managed_zone) : NULL;
    m->cfg.njalla_token = cfg.njalla_token ? strdup(cfg.njalla_token) : NULL;

    if (m->cfg.dns_provider_type) {
        if (strcmp(m->cfg.dns_provider_type, "cloudflare") == 0) {
            m->dns = portillia_cloudflare_new(m->cfg.cloudflare_token);
        } else if (strcmp(m->cfg.dns_provider_type, "gcloud") == 0) {
            m->dns = portillia_gcloud_new(m->cfg.gcp_project_id, m->cfg.gcp_managed_zone);
        } else if (strcmp(m->cfg.dns_provider_type, "route53") == 0) {
            m->dns = portillia_route53_new(cfg.aws_access_key_id, cfg.aws_secret_access_key, cfg.aws_session_token, cfg.aws_region, cfg.aws_hosted_zone_id, cfg.aws_kms_key_arn);
        }
    }

    // Ensure ACME account is set up
    ensure_acme_account(m);

    return m;
}

void portillia_acme_manager_destroy(portillia_acme_manager *m) {
    if (!m) return;
    if (m->dns) m->dns->destroy(m->dns);
    free(m->cfg.base_domain);
    free(m->cfg.key_dir);
    free(m->cfg.dns_provider_type);
    free(m->cfg.ens_gasless_address);
    free(m->cfg.cloudflare_token);
    free(m->cfg.gcp_project_id);
    free(m->cfg.gcp_managed_zone);
    free(m->cfg.njalla_token);
    free(m->cfg.aws_access_key_id); // Add these if strdup'd
    free(m->cfg.aws_secret_access_key);
    free(m->cfg.aws_session_token);
    free(m->cfg.aws_region);
    free(m->cfg.aws_hosted_zone_id);
    free(m->cfg.aws_kms_key_arn);

    if (m->acme_account_key_path) free(m->acme_account_key_path);
    if (m->acme_email) free(m->acme_email);
    free(m);
}

#include <resolv.h>
#include <arpa/nameser.h>

/**
 * @brief Simple DNS TXT record check.
 */
static bool check_dns_txt(const char *domain, const char *expected_value) {
    unsigned char nsbuf[4096];
    int len = res_query(domain, C_IN, T_TXT, nsbuf, sizeof(nsbuf));
    if (len < 0) return false;

    // Very simplified parser for TXT response
    return strstr((char *)nsbuf, expected_value) != NULL;
}

int portillia_acme_fulfill_challenge(portillia_acme_manager *m, const char *domain, const char *key_auth, bool create) {
    if (!m->dns) return CWIST_FAILURE;

    char challenge_domain[512];
    snprintf(challenge_domain, sizeof(challenge_domain), "_acme-challenge.%s", domain);

    if (create) {
        LOG_INFO("Fulfilling ACME DNS challenge: adding TXT for %s", challenge_domain);
        int res = m->dns->ensure_txt_record(m->dns, challenge_domain, key_auth);
        
        // Propagation check: Poll until record is visible
        for (int i = 0; i < 20; i++) {
            if (check_dns_txt(challenge_domain, key_auth)) {
                LOG_INFO("Verified DNS propagation for %s", challenge_domain);
                return CWIST_SUCCESS;
            }
            sleep(5);
            LOG_INFO("Waiting for DNS propagation for %s (attempt %d)...", challenge_domain, i+1);
        }
        return CWIST_FAILURE;
    } else {
        LOG_INFO("Cleaning up ACME DNS challenge: removing TXT for %s", challenge_domain);
        return m->dns->delete_txt_records(m->dns, challenge_domain, key_auth);
    }
}


int portillia_acme_manager_ensure_certificate(portillia_acme_manager *m, char **cert_file, char **key_file) {
    char cert_path[512], key_path[512];
    snprintf(cert_path, sizeof(cert_path), "%s/fullchain.pem", m->cfg.key_dir);
    snprintf(key_path, sizeof(key_path), "%s/privatekey.pem", m->cfg.key_dir);
    
    // Ensure the internal lego state directory exists within the persistent volume
    char acme_home[512];
    snprintf(acme_home, sizeof(acme_home), "%s/.lego", m->cfg.key_dir);
    mkdir(acme_home, 0700);
    
    if (access(cert_path, F_OK) == 0 && access(key_path, F_OK) == 0) {
        // Rebuild fullchain.pem from lego artifacts in case the existing one lacks the intermediate chain
        char cp_cmd[2048];
        snprintf(cp_cmd, sizeof(cp_cmd),
                 "cat %s/certificates/%s.crt %s/certificates/%s.issuer.crt > %s 2>/dev/null || true",
                 acme_home, m->cfg.base_domain, acme_home, m->cfg.base_domain, cert_path);
        system(cp_cmd);
        *cert_file = strdup(cert_path);
        *key_file = strdup(key_path);
        return CWIST_SUCCESS;
    }
    
    LOG_INFO("Certificates missing. Provisioning via lego...");
    
    char cmd[2048];
    const char *lego_dns = "";
    if (strcmp(m->cfg.dns_provider_type, "cloudflare") == 0) {
        lego_dns = "cloudflare";
        if (m->cfg.cloudflare_token) setenv("CLOUDFLARE_DNS_API_TOKEN", m->cfg.cloudflare_token, 1);
    } else if (strcmp(m->cfg.dns_provider_type, "gcloud") == 0) {
        lego_dns = "gcloud";
        if (m->cfg.gcp_project_id) setenv("GCE_PROJECT", m->cfg.gcp_project_id, 1);
    } else if (strcmp(m->cfg.dns_provider_type, "route53") == 0) {
        lego_dns = "route53";
        if (m->cfg.aws_hosted_zone_id) setenv("AWS_HOSTED_ZONE_ID", m->cfg.aws_hosted_zone_id, 1);
    } else if (strcmp(m->cfg.dns_provider_type, "njalla") == 0) {
        lego_dns = "njalla";
        if (m->cfg.njalla_token) setenv("NJALLA_TOKEN", m->cfg.njalla_token, 1);
    } else {
        LOG_ERROR("Unsupported DNS provider for lego: %s", m->cfg.dns_provider_type);
        return CWIST_FAILURE;
    }

    snprintf(cmd, sizeof(cmd), 
             "lego --accept-tos --email portal@%s --dns %s --domains %s --domains '*.%s' --path %s run", 
             m->cfg.base_domain, lego_dns, m->cfg.base_domain, m->cfg.base_domain, acme_home);
    
    int ret = system(cmd);
    
    if (ret == 0) {
        // Build fullchain.pem from leaf + intermediate; lego stores intermediate
        // in .issuer.crt by default, so concatenating is required.
        char cp_cmd[2048];
        snprintf(cp_cmd, sizeof(cp_cmd),
                 "cat %s/certificates/%s.crt %s/certificates/%s.issuer.crt > %s 2>/dev/null || cp %s/certificates/%s.crt %s",
                 acme_home, m->cfg.base_domain, acme_home, m->cfg.base_domain, cert_path,
                 acme_home, m->cfg.base_domain, cert_path);
        system(cp_cmd);
        snprintf(cp_cmd, sizeof(cp_cmd), "cp %s/certificates/%s.key %s",
                 acme_home, m->cfg.base_domain, key_path);
        system(cp_cmd);
    }

    
    if (ret == 0 && access(cert_path, F_OK) == 0 && access(key_path, F_OK) == 0) {
        *cert_file = strdup(cert_path);
        *key_file = strdup(key_path);
        return CWIST_SUCCESS;
    }
    
    return CWIST_FAILURE;
}

int portillia_acme_manager_sync_dns(portillia_acme_manager *m) {
    if (!m->dns) return CWIST_SUCCESS;

    char *public_ip = fetch_public_ip();
    if (!public_ip) {
        public_ip = strdup("127.0.0.1");
        LOG_WARN("Failed to detect public IP, falling back to %s", public_ip);
    }
    LOG_INFO("Syncing DNS A records for %s to %s using %s", m->cfg.base_domain, public_ip, m->dns->name(m->dns));
    int res = m->dns->ensure_a_records(m->dns, m->cfg.base_domain, public_ip);
    free(public_ip);
    return res;
}

int portillia_acme_manager_sync_ens_gasless(portillia_acme_manager *m) {
    if (!m->cfg.ens_gasless_enabled || !m->dns) return CWIST_SUCCESS;

    cwist_sstring *state = cwist_sstring_create();
    cwist_sstring *ds_record = cwist_sstring_create();
    cwist_sstring *message = cwist_sstring_create();

    int err = m->dns->ensure_dnssec(m->dns, m->cfg.base_domain, state, ds_record, message);
    if (err == CWIST_SUCCESS) {
        LOG_INFO("DNSSEC configured for %s: %s", m->cfg.base_domain, state->data);
        if (cwist_sstring_get_size(ds_record) > 0) {
            LOG_INFO("DS Record: %s", ds_record->data);
        }
    }

    // Sync ENS TXT record
    char txt_value[512];
    snprintf(txt_value, sizeof(txt_value), "ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01 %s", m->cfg.ens_gasless_address);
    err = m->dns->ensure_txt_record(m->dns, m->cfg.base_domain, txt_value);

    cwist_sstring_destroy(state);
    cwist_sstring_destroy(ds_record);
    cwist_sstring_destroy(message);
    
    return err;
}
