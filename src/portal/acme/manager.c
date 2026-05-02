#include <portillia/portal/acme/manager.h>
#include <portillia/portal/acme/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <portillia/utils/log.h>
#include <portillia/utils/network.h>

struct portillia_acme_manager {
    portillia_acme_config cfg;
    portillia_dns_provider *dns;
};

portillia_acme_manager* portillia_acme_manager_new(portillia_acme_config cfg) {
    portillia_acme_manager *m = calloc(1, sizeof(portillia_acme_manager));
    m->cfg = cfg;
    
    // Duplicate strings to own them
    m->cfg.base_domain = cfg.base_domain ? strdup(cfg.base_domain) : NULL;
    m->cfg.key_dir = cfg.key_dir ? strdup(cfg.key_dir) : NULL;
    m->cfg.dns_provider_type = cfg.dns_provider_type ? strdup(cfg.dns_provider_type) : NULL;
    m->cfg.ens_gasless_address = cfg.ens_gasless_address ? strdup(cfg.ens_gasless_address) : NULL;
    m->cfg.cloudflare_token = cfg.cloudflare_token ? strdup(cfg.cloudflare_token) : NULL;
    m->cfg.gcp_project_id = cfg.gcp_project_id ? strdup(cfg.gcp_project_id) : NULL;
    m->cfg.gcp_managed_zone = cfg.gcp_managed_zone ? strdup(cfg.gcp_managed_zone) : NULL;
    // ... duplicate other AWS fields if needed

    if (m->cfg.dns_provider_type) {
        if (strcmp(m->cfg.dns_provider_type, "cloudflare") == 0) {
            m->dns = portillia_cloudflare_new(m->cfg.cloudflare_token);
        } else if (strcmp(m->cfg.dns_provider_type, "gcloud") == 0) {
            m->dns = portillia_gcloud_new(m->cfg.gcp_project_id, m->cfg.gcp_managed_zone);
        } else if (strcmp(m->cfg.dns_provider_type, "route53") == 0) {
            m->dns = portillia_route53_new(cfg.aws_access_key_id, cfg.aws_secret_access_key, cfg.aws_session_token, cfg.aws_region, cfg.aws_hosted_zone_id, cfg.aws_kms_key_arn);
        }
    }

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
    // ... free other AWS fields
    free(m);
}

int portillia_acme_manager_ensure_certificate(portillia_acme_manager *m, char **cert_file, char **key_file) {
    // Placeholder for ACME provisioning. 
    // In a real 100% equivalent, this would run the ACME flow.
    // For now, we assume certificates exist or are managed manually.
    char cert_path[512], key_path[512];
    snprintf(cert_path, sizeof(cert_path), "%s/fullchain.pem", m->cfg.key_dir);
    snprintf(key_path, sizeof(key_path), "%s/privatekey.pem", m->cfg.key_dir);
    
    if (access(cert_path, F_OK) == 0 && access(key_path, F_OK) == 0) {
        *cert_file = strdup(cert_path);
        *key_file = strdup(key_path);
        return CWIST_SUCCESS;
    }
    
    LOG_WARN("Relay certificates not found in %s. Automatic ACME provisioning not yet fully implemented in C version.", m->cfg.key_dir);
    return CWIST_FAILURE;
}

int portillia_acme_manager_sync_dns(portillia_acme_manager *m) {
    if (!m->dns) return CWIST_SUCCESS;

    // In a real implementation, we would resolve the public IP.
    // Let's use a placeholder or implement a simple IP resolver.
    const char *public_ip = "127.0.0.1"; // Placeholder
    
    LOG_INFO("Syncing DNS A records for %s to %s using %s", m->cfg.base_domain, public_ip, m->dns->name(m->dns));
    return m->dns->ensure_a_records(m->dns, m->cfg.base_domain, public_ip);
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
