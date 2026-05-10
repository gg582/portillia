#include <portillia/portal/policy.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

void portillia_policy_init(portillia_policy_t *policy) {
    if (!policy) return;
    memset(policy, 0, sizeof(*policy));
    policy->approval_mode = APPROVAL_AUTO;
}

void portillia_policy_cleanup(portillia_policy_t *policy) {
    if (!policy) return;
    for (size_t i = 0; i < policy->approved_count; i++) free(policy->approved_addresses[i]);
    free(policy->approved_addresses);
    for (size_t i = 0; i < policy->denied_count; i++) free(policy->denied_addresses[i]);
    free(policy->denied_addresses);
    for (size_t i = 0; i < policy->banned_ip_count; i++) free(policy->banned_ips[i]);
    free(policy->banned_ips);
    for (size_t i = 0; i < policy->trusted_proxy_cidr_count; i++) free(policy->trusted_proxy_cidrs[i]);
    free(policy->trusted_proxy_cidrs);
    memset(policy, 0, sizeof(*policy));
}

bool portillia_policy_is_identity_approved(const portillia_policy_t *policy, const char *address) {
    if (!policy || !address) return false;
    if (policy->approval_mode == APPROVAL_AUTO) return true;
    for (size_t i = 0; i < policy->approved_count; i++) {
        if (strcasecmp(policy->approved_addresses[i], address) == 0) return true;
    }
    return false;
}

bool portillia_policy_is_identity_denied(const portillia_policy_t *policy, const char *address) {
    if (!policy || !address) return false;
    for (size_t i = 0; i < policy->denied_count; i++) {
        if (strcasecmp(policy->denied_addresses[i], address) == 0) return true;
    }
    return false;
}

bool portillia_policy_is_ip_banned(const portillia_policy_t *policy, const char *ip) {
    if (!policy || !ip) return false;
    for (size_t i = 0; i < policy->banned_ip_count; i++) {
        if (strcmp(policy->banned_ips[i], ip) == 0) return true;
    }
    return false;
}

/* Naive IPv4 CIDR prefix match for trusted-proxy detection.
 * Full CIDR parsing is overkill for typical portal deployments. */
static int cidr_prefix_match(const char *ip, const char *cidr) {
    if (!ip || !cidr) return 0;
    char buf[64];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    if (!slash) {
        return strcmp(ip, buf) == 0 ? 1 : 0;
    }
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix <= 0) return strcmp(ip, buf) == 0 ? 1 : 0;

    unsigned int ip_octets[4] = {0};
    unsigned int net_octets[4] = {0};
    if (sscanf(ip, "%u.%u.%u.%u", &ip_octets[0], &ip_octets[1], &ip_octets[2], &ip_octets[3]) != 4) return 0;
    if (sscanf(buf, "%u.%u.%u.%u", &net_octets[0], &net_octets[1], &net_octets[2], &net_octets[3]) != 4) return 0;

    unsigned int ip_u = (ip_octets[0] << 24) | (ip_octets[1] << 16) | (ip_octets[2] << 8) | ip_octets[3];
    unsigned int net_u = (net_octets[0] << 24) | (net_octets[1] << 16) | (net_octets[2] << 8) | net_octets[3];
    unsigned int mask = (prefix >= 32) ? 0xFFFFFFFFU : (0xFFFFFFFFU << (32 - prefix));
    return (ip_u & mask) == (net_u & mask) ? 1 : 0;
}

static int is_trusted_proxy(const portillia_policy_t *policy, const char *ip) {
    if (!policy || !ip) return 0;
    for (size_t i = 0; i < policy->trusted_proxy_cidr_count; i++) {
        if (cidr_prefix_match(ip, policy->trusted_proxy_cidrs[i])) return 1;
    }
    return 0;
}

char *portillia_policy_extract_client_ip(const portillia_policy_t *policy,
                                         const char *x_forwarded_for,
                                         const char *x_real_ip,
                                         const char *direct_ip) {
    if (!policy) return direct_ip ? strdup(direct_ip) : NULL;

    if (x_real_ip && is_trusted_proxy(policy, direct_ip)) {
        return strdup(x_real_ip);
    }

    if (x_forwarded_for && is_trusted_proxy(policy, direct_ip)) {
        /* Go proxy_trust.go semantics: iterate from right (closest to server)
         * to left (furthest from server), stopping at the first untrusted IP. */
        char *copy = strdup(x_forwarded_for);
        if (!copy) return direct_ip ? strdup(direct_ip) : NULL;

        /* Count commas to allocate array */
        int count = 1;
        for (char *p = copy; *p; p++) if (*p == ',') count++;
        char **parts = malloc(sizeof(char *) * count);
        if (!parts) { free(copy); return direct_ip ? strdup(direct_ip) : NULL; }

        int n = 0;
        char *save = NULL;
        for (char *tok = strtok_r(copy, ",", &save); tok && n < count; tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ' || *tok == '\t') tok++;
            size_t len = strlen(tok);
            while (len > 0 && (tok[len - 1] == ' ' || tok[len - 1] == '\t')) tok[--len] = '\0';
            parts[n++] = tok;
        }

        char *result = NULL;
        for (int i = n - 1; i >= 0; i--) {
            if (!is_trusted_proxy(policy, parts[i])) {
                result = strdup(parts[i]);
                break;
            }
        }
        free(parts);
        free(copy);
        return result ? result : (direct_ip ? strdup(direct_ip) : NULL);
    }

    return direct_ip ? strdup(direct_ip) : NULL;
}
