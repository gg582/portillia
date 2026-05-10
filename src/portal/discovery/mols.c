#include <portillia/portal/discovery/mols.h>
#include <portillia/discovery/relay_set.h>
#include <portillia/utils/log.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define MOLS_MAGIC_CONSTANT (MOLS_ORDER * MOLS_ORDER + 1) /* 4097 */

static const uint8_t mols_base_m1    = 3;
static const uint8_t mols_base_m2    = 5;
static const uint8_t mols_variant_m1 = 7;
static const uint8_t mols_variant_m2 = 11;

static const double mols_congestion_rtt_threshold_ms = 500.0;
static const double mols_cv_threshold                = 0.5;
static const double mols_fallback_rtt_threshold_ms   = 2000.0;

/* ---------- GF(64) ---------- */
static uint8_t gf64_mul(uint8_t a, uint8_t b) {
    a &= 0x3f;
    b &= 0x3f;
    uint8_t r = 0;
    while (b != 0) {
        if (b & 1) r ^= a;
        if (a & 0x20) {
            a = ((a << 1) ^ 0x43) & 0x3f;
        } else {
            a = (a << 1) & 0x3f;
        }
        b >>= 1;
    }
    return r;
}

static int grid_order_for_size(int pool_size) {
    if (pool_size <= 64) return 64;
    int rem = pool_size % 32;
    if (rem == 0) return pool_size;
    return pool_size + (32 - rem);
}

static int mols_score(int i, int j, int m1, int m2, int order) {
    if (order == 64) {
        uint8_t l1 = gf64_mul((uint8_t)m1, (uint8_t)i) ^ (uint8_t)j;
        uint8_t l2 = gf64_mul((uint8_t)m2, (uint8_t)i) ^ (uint8_t)j;
        return (int)l1 * order + (int)l2 + 1;
    }
    return ((m1 * i + j) % order) * order + ((m2 * i + j) % order) + 1;
}

static int mols_congestion_score(int i, int j, int m1, int m2, int order) {
    return (order * order + 1) - mols_score(i, (order - 1) - j, m1, m2, order);
}

static uint8_t hash_to_gf64(const char *s) {
    uint32_t h = 2166136261U;
    for (size_t i = 0; s && s[i]; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619U;
    }
    return (uint8_t)(h & 0x3f);
}

/* ---------- RTT stats ---------- */
static void mols_rtt_stats(const portillia_relay_state_t **states, int count,
                           double *out_mean_ms, double *out_cv) {
    int n = 0;
    double sum = 0.0;
    for (int i = 0; i < count; i++) {
        if (states[i]->discovery_rtt_at == 0) continue;
        n++;
        sum += states[i]->discovery_rtt_ms;
    }
    if (n == 0) {
        *out_mean_ms = 0.0;
        *out_cv = 0.0;
        return;
    }
    double avg = sum / (double)n;
    if (n == 1) {
        *out_mean_ms = avg;
        *out_cv = 0.0;
        return;
    }
    double sq = 0.0;
    for (int i = 0; i < count; i++) {
        if (states[i]->discovery_rtt_at == 0) continue;
        double d = states[i]->discovery_rtt_ms - avg;
        sq += d * d;
    }
    double stddev = sqrt(sq / (double)n);
    *out_mean_ms = avg;
    *out_cv = (avg > 0.0) ? (stddev / avg) : 0.0;
}

static int is_relay_fallback(const portillia_relay_state_t *state) {
    return state->discovery_rtt_at != 0 && state->discovery_rtt_ms > mols_fallback_rtt_threshold_ms;
}

/* ---------- Candidate ranking ---------- */

typedef struct {
    const portillia_relay_state_t *state;
    int score;
    int seq;
} mols_candidate;

static int better_mols_candidate(const mols_candidate *a, const mols_candidate *b) {
    if (a->score != b->score) return a->score > b->score ? 1 : 0;
    if (a->state->confirmed != b->state->confirmed) return a->state->confirmed ? 1 : 0;
    const char *aurl = a->state->descriptor.api_https_addr ? a->state->descriptor.api_https_addr : "";
    const char *burl = b->state->descriptor.api_https_addr ? b->state->descriptor.api_https_addr : "";
    int cmp = strcmp(aurl, burl);
    if (cmp != 0) return cmp < 0 ? 1 : 0;
    return a->seq < b->seq ? 1 : 0;
}

static char **rank_relay_pool(const portillia_relay_state_t **pool, int pool_count,
                              const char *local_address, size_t *out_count) {
    *out_count = 0;
    if (pool_count == 0) return NULL;

    uint8_t ingress_idx = hash_to_gf64(local_address);
    double avg_rtt_ms, cv;
    mols_rtt_stats(pool, pool_count, &avg_rtt_ms, &cv);
    int congested = avg_rtt_ms > mols_congestion_rtt_threshold_ms;
    int non_linear = cv > mols_cv_threshold;

    int m1 = mols_base_m1;
    int m2 = mols_base_m2;
    if (non_linear) {
        m1 = mols_variant_m1;
        m2 = mols_variant_m2;
    }

    int order = grid_order_for_size(pool_count);

    /* Partition active / fallback */
    const portillia_relay_state_t *active[256];
    const portillia_relay_state_t *fallback[256];
    int active_n = 0, fallback_n = 0;
    for (int i = 0; i < pool_count; i++) {
        if (is_relay_fallback(pool[i])) {
            if (fallback_n < 256) fallback[fallback_n++] = pool[i];
        } else {
            if (active_n < 256) active[active_n++] = pool[i];
        }
    }

    if (active_n < MOLS_MIN_ACTIVE_NODES && fallback_n > 0) {
        /* Promote fastest fallbacks (bubble sort for small N) */
        for (int i = 0; i < fallback_n - 1; i++) {
            for (int j = i + 1; j < fallback_n; j++) {
                if (fallback[j]->discovery_rtt_ms < fallback[i]->discovery_rtt_ms) {
                    const portillia_relay_state_t *tmp = fallback[i];
                    fallback[i] = fallback[j];
                    fallback[j] = tmp;
                }
            }
        }
        int promote = MOLS_MIN_ACTIVE_NODES - active_n;
        if (promote > fallback_n) promote = fallback_n;
        for (int i = 0; i < promote; i++) active[active_n++] = fallback[i];
        for (int i = 0; i < fallback_n - promote; i++) fallback[i] = fallback[i + promote];
        fallback_n -= promote;
    }

    size_t active_urls_count = 0;
    size_t fallback_urls_count = 0;
    char **active_urls = NULL;
    char **fallback_urls = NULL;

    /* rank_tier inlined for active */
    {
        int tier_count = active_n;
        const portillia_relay_state_t * const *tier = active;
        if (tier_count > 0) {
            mols_candidate candidates[MOLS_CANDIDATE_DEPTH];
            int count = 0;
            for (int i = 0; i < tier_count; i++) {
                uint8_t candidate_idx = hash_to_gf64(tier[i]->descriptor.api_https_addr ? tier[i]->descriptor.api_https_addr : "");
                int idx = (int)candidate_idx % order;
                int sc = congested ? mols_congestion_score((int)ingress_idx % order, idx, m1, m2, order)
                                   : mols_score((int)ingress_idx % order, idx, m1, m2, order);
                mols_candidate cand = { .state = tier[i], .score = sc, .seq = i };
                int insert_at = count;
                while (insert_at > 0 && better_mols_candidate(&cand, &candidates[insert_at - 1])) {
                    if (insert_at < MOLS_CANDIDATE_DEPTH) candidates[insert_at] = candidates[insert_at - 1];
                    insert_at--;
                }
                if (insert_at >= MOLS_CANDIDATE_DEPTH) continue;
                candidates[insert_at] = cand;
                if (count < MOLS_CANDIDATE_DEPTH) count++;
            }
            active_urls = malloc(sizeof(char *) * (size_t)count);
            if (active_urls) {
                int out_n = 0;
                for (int i = 0; i < count; i++) {
                    if (!candidates[i].state->is_saturated) {
                        active_urls[out_n++] = strdup(candidates[i].state->descriptor.api_https_addr ? candidates[i].state->descriptor.api_https_addr : "");
                    }
                }
                for (int i = 0; i < count; i++) {
                    if (candidates[i].state->is_saturated) {
                        active_urls[out_n++] = strdup(candidates[i].state->descriptor.api_https_addr ? candidates[i].state->descriptor.api_https_addr : "");
                    }
                }
                active_urls_count = (size_t)out_n;
            }
        }
    }

    /* rank_tier inlined for fallback */
    {
        int tier_count = fallback_n;
        const portillia_relay_state_t * const *tier = fallback;
        if (tier_count > 0) {
            mols_candidate candidates[MOLS_CANDIDATE_DEPTH];
            int count = 0;
            for (int i = 0; i < tier_count; i++) {
                uint8_t candidate_idx = hash_to_gf64(tier[i]->descriptor.api_https_addr ? tier[i]->descriptor.api_https_addr : "");
                int idx = (int)candidate_idx % order;
                int sc = congested ? mols_congestion_score((int)ingress_idx % order, idx, m1, m2, order)
                                   : mols_score((int)ingress_idx % order, idx, m1, m2, order);
                mols_candidate cand = { .state = tier[i], .score = sc, .seq = i };
                int insert_at = count;
                while (insert_at > 0 && better_mols_candidate(&cand, &candidates[insert_at - 1])) {
                    if (insert_at < MOLS_CANDIDATE_DEPTH) candidates[insert_at] = candidates[insert_at - 1];
                    insert_at--;
                }
                if (insert_at >= MOLS_CANDIDATE_DEPTH) continue;
                candidates[insert_at] = cand;
                if (count < MOLS_CANDIDATE_DEPTH) count++;
            }
            fallback_urls = malloc(sizeof(char *) * (size_t)count);
            if (fallback_urls) {
                int out_n = 0;
                for (int i = 0; i < count; i++) {
                    if (!candidates[i].state->is_saturated) {
                        fallback_urls[out_n++] = strdup(candidates[i].state->descriptor.api_https_addr ? candidates[i].state->descriptor.api_https_addr : "");
                    }
                }
                for (int i = 0; i < count; i++) {
                    if (candidates[i].state->is_saturated) {
                        fallback_urls[out_n++] = strdup(candidates[i].state->descriptor.api_https_addr ? candidates[i].state->descriptor.api_https_addr : "");
                    }
                }
                fallback_urls_count = (size_t)out_n;
            }
        }
    }

    size_t total = active_urls_count + fallback_urls_count;
    char **result = malloc(sizeof(char *) * total);
    if (!result) {
        for (size_t i = 0; i < active_urls_count; i++) free(active_urls[i]);
        free(active_urls);
        for (size_t i = 0; i < fallback_urls_count; i++) free(fallback_urls[i]);
        free(fallback_urls);
        return NULL;
    }
    size_t pos = 0;
    for (size_t i = 0; i < active_urls_count; i++) result[pos++] = active_urls[i];
    for (size_t i = 0; i < fallback_urls_count; i++) result[pos++] = fallback_urls[i];
    free(active_urls);
    free(fallback_urls);
    *out_count = pos;
    return result;
}

/* ---------- Public selectors ---------- */

char **mols_select_priority(portillia_relay_state_t **states, int count,
                            const char *local_address,
                            int require_udp, int require_tcp,
                            int max_active_relays,
                            size_t *out_count) {
    *out_count = 0;
    if (!states || count == 0) return NULL;

    time_t now = time(NULL);
    const portillia_relay_state_t *auto_pool[256];
    int auto_n = 0;

    for (int i = 0; i < count; i++) {
        const portillia_relay_state_t *s = states[i];
        if (s->banned) continue;
        const char *relay_url = s->descriptor.api_https_addr ? s->descriptor.api_https_addr : "";
        if (s->descriptor.address && s->descriptor.address[0]) {
            if (s->descriptor.expires_at <= now) continue;
            if (require_udp && !s->descriptor.supports_udp) continue;
            if (require_tcp && !s->descriptor.supports_tcp) continue;
        }
        if (s->suppress_active_until > now) continue;
        if (auto_n < 256) auto_pool[auto_n++] = s;
    }

    size_t ranked_count = 0;
    char **ranked = rank_relay_pool(auto_pool, auto_n, local_address, &ranked_count);
    if (!ranked) return NULL;

    if (max_active_relays <= 0) max_active_relays = MOLS_DEFAULT_MAX_ACTIVE_RELAYS;
    if (ranked_count > (size_t)max_active_relays) ranked_count = (size_t)max_active_relays;

    *out_count = ranked_count;
    return ranked;
}

char **mols_select_multihop(portillia_relay_state_t **states, int count,
                            const char *local_address,
                            int require_udp, int require_tcp,
                            int multi_hop_depth,
                            size_t *out_count) {
    *out_count = 0;
    if (!states || count == 0 || multi_hop_depth <= 1) return NULL;

    time_t now = time(NULL);
    const portillia_relay_state_t *auto_pool[256];
    int auto_n = 0;

    for (int i = 0; i < count; i++) {
        const portillia_relay_state_t *s = states[i];
        if (s->banned) continue;
        if (!s->descriptor.address || !s->descriptor.address[0]) continue;
        if (s->descriptor.expires_at <= now) continue;
        if (require_udp && !s->descriptor.supports_udp) continue;
        if (require_tcp && !s->descriptor.supports_tcp) continue;
        if (!s->descriptor.supports_overlay) continue;
        const char *wgpk = s->descriptor.wireguard_public_key ? s->descriptor.wireguard_public_key : "";
        if (!wgpk[0]) continue;
        if (s->descriptor.wireguard_port <= 0 || s->descriptor.wireguard_port > 65535) continue;
        if (s->suppress_active_until > now) continue;
        if (auto_n < 256) auto_pool[auto_n++] = s;
    }

    size_t ranked_count = 0;
    char **ranked = rank_relay_pool(auto_pool, auto_n, local_address, &ranked_count);
    if (!ranked) return NULL;

    if (ranked_count > (size_t)multi_hop_depth) ranked_count = (size_t)multi_hop_depth;

    *out_count = ranked_count;
    return ranked;
}
