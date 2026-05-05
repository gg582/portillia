/** @file types.c
 * @brief Implementation of Portillia type lifecycle helpers.
 */

#include <portillia/types/types.h>
#include <string.h>
#include <unistd.h>

/* ---------- Identity ---------- */

void portillia_identity_init(portillia_identity_t *id) {
    if (!id) return;
    memset(id, 0, sizeof(*id));
}

void portillia_identity_cleanup(portillia_identity_t *id) {
    if (!id) return;
    if (id->name) portillia_gc_free_later(id->name);
    if (id->address) portillia_gc_free_later(id->address);
    if (id->public_key) portillia_gc_free_later(id->public_key);
    if (id->private_key) portillia_gc_free_later(id->private_key);
    memset(id, 0, sizeof(*id));
}

void portillia_identity_copy(portillia_identity_t *dst, const portillia_identity_t *src) {
    if (!dst || !src) return;
    portillia_identity_cleanup(dst);
    if (src->name) dst->name = portillia_gc_strdup(src->name);
    if (src->address) dst->address = portillia_gc_strdup(src->address);
    if (src->public_key) dst->public_key = portillia_gc_strdup(src->public_key);
    if (src->private_key) dst->private_key = portillia_gc_strdup(src->private_key);
}

/* ---------- Relay Identity ---------- */

void portillia_relay_identity_init(portillia_relay_identity_t *id) {
    if (!id) return;
    memset(id, 0, sizeof(*id));
}

void portillia_relay_identity_cleanup(portillia_relay_identity_t *id) {
    if (!id) return;
    portillia_identity_cleanup(&id->base);
    if (id->admin_secret_key) portillia_gc_free_later(id->admin_secret_key);
    if (id->wireguard_public_key) portillia_gc_free_later(id->wireguard_public_key);
    if (id->wireguard_private_key) portillia_gc_free_later(id->wireguard_private_key);
    if (id->encrypted_client_hello_seed) portillia_gc_free_later(id->encrypted_client_hello_seed);
    memset(id, 0, sizeof(*id));
}

/* ---------- Lease Metadata ---------- */

void portillia_lease_metadata_init(portillia_lease_metadata_t *m) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
}

void portillia_lease_metadata_cleanup(portillia_lease_metadata_t *m) {
    if (!m) return;
    if (m->description) portillia_gc_free_later(m->description);
    if (m->owner) portillia_gc_free_later(m->owner);
    if (m->thumbnail) portillia_gc_free_later(m->thumbnail);
    if (m->tags) {
        for (size_t i = 0; i < m->tags_count; i++) {
            if (m->tags[i]) portillia_gc_free_later(m->tags[i]);
        }
        portillia_gc_free_later(m->tags);
    }
    memset(m, 0, sizeof(*m));
}

void portillia_lease_metadata_copy(portillia_lease_metadata_t *dst, const portillia_lease_metadata_t *src) {
    if (!dst || !src) return;
    portillia_lease_metadata_cleanup(dst);
    if (src->description) dst->description = portillia_gc_strdup(src->description);
    if (src->owner) dst->owner = portillia_gc_strdup(src->owner);
    if (src->thumbnail) dst->thumbnail = portillia_gc_strdup(src->thumbnail);
    dst->hide = src->hide;
    if (src->tags_count > 0 && src->tags) {
        dst->tags = (char **)portillia_gc_alloc(sizeof(char *) * src->tags_count);
        if (dst->tags) {
            dst->tags_count = src->tags_count;
            for (size_t i = 0; i < src->tags_count; i++) {
                dst->tags[i] = src->tags[i] ? portillia_gc_strdup(src->tags[i]) : NULL;
            }
        }
    }
}

/* ---------- Lease ---------- */

void portillia_lease_init(portillia_lease_t *l) {
    if (!l) return;
    memset(l, 0, sizeof(*l));
}

void portillia_lease_cleanup(portillia_lease_t *l) {
    if (!l) return;
    if (l->name) portillia_gc_free_later(l->name);
    if (l->hostname) portillia_gc_free_later(l->hostname);
    if (l->tcp_addr) portillia_gc_free_later(l->tcp_addr);
    if (l->hop_token) portillia_gc_free_later(l->hop_token);
    if (l->hop_next_overlay_ipv4) portillia_gc_free_later(l->hop_next_overlay_ipv4);
    if (l->hop_next_token) portillia_gc_free_later(l->hop_next_token);
    portillia_lease_metadata_cleanup(&l->metadata);
    memset(l, 0, sizeof(*l));
}

void portillia_lease_copy(portillia_lease_t *dst, const portillia_lease_t *src) {
    if (!dst || !src) return;
    portillia_lease_cleanup(dst);
    if (src->name) dst->name = portillia_gc_strdup(src->name);
    if (src->hostname) dst->hostname = portillia_gc_strdup(src->hostname);
    dst->expires_at = src->expires_at;
    dst->first_seen_at = src->first_seen_at;
    dst->last_seen_at = src->last_seen_at;
    dst->udp_enabled = src->udp_enabled;
    dst->tcp_enabled = src->tcp_enabled;
    if (src->tcp_addr) dst->tcp_addr = portillia_gc_strdup(src->tcp_addr);
    portillia_lease_metadata_copy(&dst->metadata, &src->metadata);
    dst->ready = src->ready;
    if (src->hop_token) dst->hop_token = portillia_gc_strdup(src->hop_token);
    if (src->hop_next_overlay_ipv4) dst->hop_next_overlay_ipv4 = portillia_gc_strdup(src->hop_next_overlay_ipv4);
    if (src->hop_next_token) dst->hop_next_token = portillia_gc_strdup(src->hop_next_token);
}

/* ---------- Relay Descriptor ---------- */

void portillia_relay_descriptor_init(portillia_relay_descriptor_t *d) {
    if (!d) return;
    memset(d, 0, sizeof(*d));
}

void portillia_relay_descriptor_cleanup(portillia_relay_descriptor_t *d) {
    if (!d) return;
    if (d->address) portillia_gc_free_later(d->address);
    if (d->version) portillia_gc_free_later(d->version);
    if (d->api_https_addr) portillia_gc_free_later(d->api_https_addr);
    if (d->wireguard_public_key) portillia_gc_free_later(d->wireguard_public_key);
    if (d->signature) portillia_gc_free_later(d->signature);
    memset(d, 0, sizeof(*d));
}

void portillia_relay_descriptor_copy(portillia_relay_descriptor_t *dst, const portillia_relay_descriptor_t *src) {
    if (!dst || !src) return;
    portillia_relay_descriptor_cleanup(dst);
    if (src->address) dst->address = portillia_gc_strdup(src->address);
    if (src->version) dst->version = portillia_gc_strdup(src->version);
    dst->issued_at = src->issued_at;
    dst->expires_at = src->expires_at;
    if (src->api_https_addr) dst->api_https_addr = portillia_gc_strdup(src->api_https_addr);
    if (src->wireguard_public_key) dst->wireguard_public_key = portillia_gc_strdup(src->wireguard_public_key);
    dst->wireguard_port = src->wireguard_port;
    dst->supports_overlay = src->supports_overlay;
    dst->supports_udp = src->supports_udp;
    dst->supports_tcp = src->supports_tcp;
    dst->active_connections = src->active_connections;
    dst->tcp_bps = src->tcp_bps;
    if (src->signature) dst->signature = portillia_gc_strdup(src->signature);
}

/* ---------- Datagram Frame ---------- */

void portillia_datagram_frame_init(portillia_datagram_frame_t *f) {
    if (!f) return;
    memset(f, 0, sizeof(*f));
}

void portillia_datagram_frame_cleanup(portillia_datagram_frame_t *f) {
    if (!f) return;
    if (f->payload) portillia_gc_free_later(f->payload);
    if (f->address) portillia_gc_free_later(f->address);
    if (f->relay_url) portillia_gc_free_later(f->relay_url);
    if (f->udp_addr) portillia_gc_free_later(f->udp_addr);
    memset(f, 0, sizeof(*f));
}

void portillia_datagram_frame_copy(portillia_datagram_frame_t *dst, const portillia_datagram_frame_t *src) {
    if (!dst || !src) return;
    portillia_datagram_frame_cleanup(dst);
    dst->flow_id = src->flow_id;
    if (src->payload_len > 0 && src->payload) {
        dst->payload = (uint8_t *)portillia_gc_alloc(src->payload_len);
        if (dst->payload) {
            dst->payload_len = src->payload_len;
            memcpy(dst->payload, src->payload, src->payload_len);
        }
    }
    if (src->address) dst->address = portillia_gc_strdup(src->address);
    if (src->relay_url) dst->relay_url = portillia_gc_strdup(src->relay_url);
    if (src->udp_addr) dst->udp_addr = portillia_gc_strdup(src->udp_addr);
}

/* ---------- Hop Route ---------- */

void portillia_hop_route_init(portillia_hop_route_t *r) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

void portillia_hop_route_cleanup(portillia_hop_route_t *r) {
    if (!r) return;
    if (r->owner_public_key) portillia_gc_free_later(r->owner_public_key);
    if (r->relay_url) portillia_gc_free_later(r->relay_url);
    if (r->match_hostname) portillia_gc_free_later(r->match_hostname);
    if (r->match_token) portillia_gc_free_later(r->match_token);
    portillia_lease_metadata_cleanup(&r->metadata);
    portillia_relay_descriptor_cleanup(&r->forward_relay);
    if (r->forward_token) portillia_gc_free_later(r->forward_token);
    if (r->signature) portillia_gc_free_later(r->signature);
    memset(r, 0, sizeof(*r));
}

void portillia_hop_route_copy(portillia_hop_route_t *dst, const portillia_hop_route_t *src) {
    if (!dst || !src) return;
    portillia_hop_route_cleanup(dst);
    if (src->owner_public_key) dst->owner_public_key = portillia_gc_strdup(src->owner_public_key);
    if (src->relay_url) dst->relay_url = portillia_gc_strdup(src->relay_url);
    if (src->match_hostname) dst->match_hostname = portillia_gc_strdup(src->match_hostname);
    if (src->match_token) dst->match_token = portillia_gc_strdup(src->match_token);
    portillia_lease_metadata_copy(&dst->metadata, &src->metadata);
    portillia_relay_descriptor_copy(&dst->forward_relay, &src->forward_relay);
    if (src->forward_token) dst->forward_token = portillia_gc_strdup(src->forward_token);
    dst->first_seen_at = src->first_seen_at;
    dst->expires_at = src->expires_at;
    if (src->signature) dst->signature = portillia_gc_strdup(src->signature);
}

/* ---------- Agent Status ---------- */

void portillia_agent_relay_status_init(portillia_agent_relay_status_t *s) {
    if (!s) return;
    memset(s, 0, sizeof(*s));
}

void portillia_agent_relay_status_cleanup(portillia_agent_relay_status_t *s) {
    if (!s) return;
    if (s->relay_url) portillia_gc_free_later(s->relay_url);
    if (s->public_url) portillia_gc_free_later(s->public_url);
    memset(s, 0, sizeof(*s));
}

void portillia_agent_tunnel_status_init(portillia_agent_tunnel_status_t *s) {
    if (!s) return;
    memset(s, 0, sizeof(*s));
}

void portillia_agent_tunnel_status_cleanup(portillia_agent_tunnel_status_t *s) {
    if (!s) return;
    if (s->id) portillia_gc_free_later(s->id);
    if (s->name) portillia_gc_free_later(s->name);
    if (s->state) portillia_gc_free_later(s->state);
    if (s->target_addr) portillia_gc_free_later(s->target_addr);
    if (s->last_error) portillia_gc_free_later(s->last_error);
    if (s->multi_hop) {
        for (size_t i = 0; i < s->multi_hop_count; i++) {
            if (s->multi_hop[i]) portillia_gc_free_later(s->multi_hop[i]);
        }
        portillia_gc_free_later(s->multi_hop);
    }
    if (s->relays) {
        for (size_t i = 0; i < s->relays_count; i++) {
            portillia_agent_relay_status_cleanup(&s->relays[i]);
        }
        portillia_gc_free_later(s->relays);
    }
    memset(s, 0, sizeof(*s));
}

/* ---------- Net Connection ---------- */

void portillia_net_conn_init(portillia_net_conn_t *c) {
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

void portillia_net_conn_cleanup(portillia_net_conn_t *c) {
    if (!c) return;
    if (c->ssl && c->owns_ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->outer_ssl && c->owns_ssl) {
        SSL_shutdown(c->outer_ssl);
        SSL_free(c->outer_ssl);
    }
    if (c->fd >= 0) {
        close(c->fd);
    }
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

/* ---------- Discovery Response ---------- */

void portillia_discovery_response_init(portillia_discovery_response_t *r) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

void portillia_discovery_response_cleanup(portillia_discovery_response_t *r) {
    if (!r) return;
    if (r->protocol_version) portillia_gc_free_later(r->protocol_version);
    if (r->relays) {
        for (size_t i = 0; i < r->relays_count; i++) {
            portillia_relay_descriptor_cleanup(&r->relays[i]);
        }
        portillia_gc_free_later(r->relays);
    }
    memset(r, 0, sizeof(*r));
}

void portillia_domain_response_cleanup(portillia_domain_response_t *r) {
    if (!r) return;
    if (r->protocol_version) portillia_gc_free_later(r->protocol_version);
    if (r->sdk_version) portillia_gc_free_later(r->sdk_version);
    if (r->discovery_version) portillia_gc_free_later(r->discovery_version);
    memset(r, 0, sizeof(*r));
}

void portillia_register_challenge_response_cleanup(portillia_register_challenge_response_t *r) {
    if (!r) return;
    if (r->challenge_id) portillia_gc_free_later(r->challenge_id);
    if (r->siwe_message) portillia_gc_free_later(r->siwe_message);
    memset(r, 0, sizeof(*r));
}

void portillia_register_response_cleanup(portillia_register_response_t *r) {
    if (!r) return;
    portillia_identity_cleanup(&r->identity);
    if (r->hostname) portillia_gc_free_later(r->hostname);
    if (r->access_token) portillia_gc_free_later(r->access_token);
    if (r->keyless_url) portillia_gc_free_later(r->keyless_url);
    if (r->udp_addr) portillia_gc_free_later(r->udp_addr);
    if (r->tcp_addr) portillia_gc_free_later(r->tcp_addr);
    memset(r, 0, sizeof(*r));
}

void portillia_renew_response_cleanup(portillia_renew_response_t *r) {
    if (!r) return;
    if (r->access_token) portillia_gc_free_later(r->access_token);
    memset(r, 0, sizeof(*r));
}
