#ifndef PORTILLIA_PORTAL_POLICY_H
#define PORTILLIA_PORTAL_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    APPROVAL_AUTO = 0,
    APPROVAL_MANUAL,
} approval_mode_t;

typedef struct {
    approval_mode_t approval_mode;
    bool landing_page_enabled;

    char **approved_addresses;
    size_t approved_count;
    char **denied_addresses;
    size_t denied_count;

    char **banned_ips;
    size_t banned_ip_count;

    char **trusted_proxy_cidrs;
    size_t trusted_proxy_cidr_count;

    int64_t default_bps;
} portillia_policy_t;

void portillia_policy_init(portillia_policy_t *policy);
void portillia_policy_cleanup(portillia_policy_t *policy);

bool portillia_policy_is_identity_approved(const portillia_policy_t *policy, const char *address);
bool portillia_policy_is_identity_denied(const portillia_policy_t *policy, const char *address);
bool portillia_policy_is_ip_banned(const portillia_policy_t *policy, const char *ip);

/* Extract client IP from X-Forwarded-For / X-Real-IP using trusted proxy CIDRs.
 * Returns a malloc'd string, or NULL if no trusted proxy path. */
char *portillia_policy_extract_client_ip(const portillia_policy_t *policy,
                                         const char *x_forwarded_for,
                                         const char *x_real_ip,
                                         const char *direct_ip);

#endif
