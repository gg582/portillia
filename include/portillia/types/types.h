/** @file types.h
 * @brief Core Portillia data structures — 1:1 C port of portal-tunnel types package.
 *
 * All heap-embedded pointers are owned by the global EpochGC.
 * Use portillia_gc_alloc / portillia_gc_free_later for lifecycle management.
 */
#ifndef PORTILLIA_TYPES_H
#define PORTILLIA_TYPES_H

#include <portillia/mem/gc.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Version constants ---------- */
extern const char *PORTILLIA_RELEASE_VERSION;
extern const char *PORTILLIA_SDK_VERSION;
extern const char *PORTILLIA_DISCOVERY_VERSION;
extern const char *PORTILLIA_PORTAL_RELAY_REGISTRY_URL;
extern const char *PORTILLIA_OFFICIAL_RELEASE_BASE_URL;

void portillia_manifest_init(void);

#define PORTILLIA_HEADER_ACCESS_TOKEN     "X-Portal-Access-Token"
#define PORTILLIA_MARKER_KEEPALIVE        0x00
#define PORTILLIA_MARKER_RAW_START        0x01
#define PORTILLIA_MARKER_TLS_START        0x02

/* ---------- Net address ---------- */

typedef struct portillia_net_addr {
    char network[16];
    char address[256];
} portillia_net_addr_t;

/* ---------- Net connection ---------- */

typedef struct portillia_net_conn {
    int fd;
    SSL *ssl;          /**< inner TLS (claimed session) */
    SSL *outer_ssl;    /**< outer TLS (reverse transport) */
    bool owns_ssl;
    portillia_net_addr_t local;
    portillia_net_addr_t remote;
    bool closed;
} portillia_net_conn_t;

/* ---------- Identity ---------- */

typedef struct portillia_identity {
    char *name;        /**< may be NULL */
    char *address;     /**< EVM address, e.g. 0x... */
    char *public_key;  /**< json:"-"  — excluded from serialization */
    char *private_key; /**< json:"-"  — excluded from serialization */
} portillia_identity_t;

typedef struct portillia_relay_identity {
    portillia_identity_t base;
    char *admin_secret_key;       /**< json:"-" */
    char *wireguard_public_key;   /**< json:"-" */
    char *wireguard_private_key;  /**< json:"-" */
    char *encrypted_client_hello_seed; /**< json:"-" */
} portillia_relay_identity_t;

/* ---------- Lease & Metadata ---------- */

typedef struct portillia_lease_metadata {
    char *description;
    char *owner;
    char *thumbnail;
    char **tags;
    size_t tags_count;
    bool hide;
} portillia_lease_metadata_t;

typedef struct portillia_lease {
    char *name;
    char *hostname;
    time_t expires_at;
    time_t first_seen_at;
    time_t last_seen_at;
    bool udp_enabled;
    bool tcp_enabled;
    char *tcp_addr;
    portillia_lease_metadata_t metadata;
    int ready;

    /* Privacy / ECH fields */
    char *client_ip;
    char *reported_ip;
    char *hostname_hash;
    uint8_t *ech_config_list;
    size_t ech_config_list_len;
    char *ech_dns_hostname;

    /* Multi-hop fields */
    char *hop_token;
    char *hop_next_overlay_ipv4;
    char *hop_next_token;
} portillia_lease_t;

typedef struct portillia_admin_lease {
    portillia_lease_t base;
    char *identity_key;
    char *address;
    int64_t bps;
    char *client_ip;
    char *reported_ip;
    bool is_approved;
    bool is_banned;
    bool is_denied;
    bool is_ip_banned;
} portillia_admin_lease_t;

/* ---------- Relay Descriptor ---------- */

typedef struct portillia_relay_descriptor {
    char *address;
    char *version;
    uint64_t sequence;
    uint32_t version_val;
    time_t issued_at;
    time_t expires_at;
    char *api_https_addr;
    char *wireguard_public_key;
    int wireguard_port;
    char *overlay_ipv4;
    char **overlay_cidrs;
    size_t overlay_cidrs_count;
    bool supports_overlay;
    bool supports_overlay_peer;
    bool supports_udp;
    bool supports_tcp;
    int64_t active_connections;
    double tcp_bps;
    double load;
    double load_score;
    int64_t last_updated;
    char *signature;
} portillia_relay_descriptor_t;

typedef struct portillia_relay_descriptor portillia_relay_descriptor;

/* ---------- Transport ---------- */

typedef struct portillia_datagram_frame {
    uint32_t flow_id;
    uint8_t *payload;
    size_t payload_len;
    char *address;
    char *relay_url;
    char *udp_addr;
} portillia_datagram_frame_t;

/* ---------- API Envelope ---------- */

typedef struct portillia_api_error {
    char *code;
    char *message;
} portillia_api_error_t;

typedef struct portillia_api_request_error {
    int status_code;
    char *code;
    char *message;
} portillia_api_request_error_t;

#define PORTILLIA_API_ENVELOPE_DECL(T, name) \
    typedef struct portillia_api_envelope_##name { \
        T data; \
        portillia_api_error_t *error; \
        bool ok; \
    } portillia_api_envelope_##name##_t

/* ---------- API Request / Response structs ---------- */

typedef struct portillia_register_request {
    char *challenge_id;
    char *siwe_message;
    char *siwe_signature;
    char *reported_ip;
} portillia_register_request_t;

typedef struct portillia_register_challenge_request {
    portillia_identity_t identity;
    portillia_lease_metadata_t metadata;
    int ttl;
    bool udp_enabled;
    bool tcp_enabled;
    char *hop_token;
    char *route_hostname;
    char *hostname_hash;
    uint8_t *ech_config_list;
    size_t ech_config_list_len;
} portillia_register_challenge_request_t;

typedef struct portillia_register_challenge_response {
    char *challenge_id;
    time_t expires_at;
    char *siwe_message;
} portillia_register_challenge_response_t;

typedef struct portillia_register_response {
    portillia_identity_t identity;
    time_t expires_at;
    char *hostname;
    char *access_token;
    char *keyless_url;
    int sni_port;
    char *udp_addr;
    bool udp_enabled;
    char *tcp_addr;
    bool tcp_enabled;
} portillia_register_response_t;

typedef struct portillia_renew_request {
    char *access_token;
    int ttl;
    char *reported_ip;
} portillia_renew_request_t;

typedef struct portillia_renew_response {
    time_t expires_at;
    char *access_token;
} portillia_renew_response_t;

typedef struct portillia_unregister_request {
    char *access_token;
} portillia_unregister_request_t;

typedef struct portillia_hop_route {
    char *owner_public_key;
    char *relay_url;
    char *public_hostname;
    char *route_hostname;
    char *hostname_hash;
    uint8_t *ech_config_list;
    size_t ech_config_list_len;
    char *match_token;
    portillia_lease_metadata_t metadata;
    portillia_relay_descriptor_t forward_relay;
    char *forward_token;
    time_t first_seen_at;
    time_t expires_at;
    char *signature;
} portillia_hop_route_t;

typedef struct portillia_discovery_response {
    char *protocol_version;
    time_t generated_at;
    portillia_relay_descriptor_t *relays;
    size_t relays_count;
} portillia_discovery_response_t;

typedef struct portillia_discovery_announce_request {
    char *protocol_version;
    portillia_relay_descriptor_t descriptor;
} portillia_discovery_announce_request_t;

typedef struct portillia_discovery_announce_response {
    char *protocol_version;
    bool accepted;
} portillia_discovery_announce_response_t;

/* ---------- Agent Status ---------- */

typedef struct portillia_agent_relay_status {
    char *relay_url;
    char *public_url;
    bool connecting;
    bool bootstrap;
    bool banned;
    bool supports_overlay;
    bool supports_udp;
    bool supports_tcp;
} portillia_agent_relay_status_t;

typedef struct portillia_agent_tunnel_status {
    char *id;
    char *name;
    char *state;
    char *target_addr;
    char *last_error;
    char **multi_hop;
    size_t multi_hop_count;
    portillia_agent_relay_status_t *relays;
    size_t relays_count;
} portillia_agent_tunnel_status_t;

typedef struct portillia_agent_status_response {
    char *control_addr;
    portillia_agent_tunnel_status_t *tunnels;
    size_t tunnels_count;
} portillia_agent_status_response_t;

typedef struct portillia_agent_tunnel_request {
    char *id;
    char *name;
    char *target_addr;
    char **relay_urls;
    size_t relay_urls_count;
} portillia_agent_tunnel_request_t;

typedef struct portillia_agent_relay_request {
    char *relay_url;
} portillia_agent_relay_request_t;

typedef struct portillia_agent_multi_hop_request {
    char **relays;
    size_t relays_count;
} portillia_agent_multi_hop_request_t;

/* ---------- Admin API types ---------- */

typedef struct portillia_domain_response {
    char *protocol_version;
    char *release_version;
} portillia_domain_response_t;

typedef struct portillia_tunnel_status_response {
    char *target_addr;
    char *hostname;
    time_t expires_at;
    bool ready;
} portillia_tunnel_status_response_t;

typedef struct portillia_admin_login_request {
    char *key;
} portillia_admin_login_request_t;

typedef struct portillia_admin_login_response {
    bool success;
} portillia_admin_login_response_t;

typedef struct portillia_admin_auth_status_response {
    bool authenticated;
    bool auth_enabled;
    char *username;
} portillia_admin_auth_status_response_t;

typedef struct portillia_admin_approval_mode_request {
    char *mode;
} portillia_admin_approval_mode_request_t;

typedef struct portillia_admin_approval_mode_response {
    char *approval_mode;
} portillia_admin_approval_mode_response_t;

typedef struct portillia_admin_landing_page_settings_request {
    bool enabled;
} portillia_admin_landing_page_settings_request_t;

typedef struct portillia_admin_landing_page_settings_response {
    bool enabled;
} portillia_admin_landing_page_settings_response_t;

typedef struct portillia_admin_bps_request {
    char *address;
    int64_t bps;
} portillia_admin_bps_request_t;

typedef struct portillia_admin_udp_settings_request {
    bool enabled;
    int max_leases;
} portillia_admin_udp_settings_request_t;

typedef struct portillia_admin_udp_settings_response {
    bool enabled;
    int max_leases;
} portillia_admin_udp_settings_response_t;

typedef struct portillia_admin_tcp_port_settings_request {
    bool enabled;
    int max_leases;
} portillia_admin_tcp_port_settings_request_t;

typedef struct portillia_admin_tcp_port_settings_response {
    bool enabled;
    int max_leases;
} portillia_admin_tcp_port_settings_response_t;

typedef struct portillia_admin_snapshot_response {
    char *approval_mode;
    bool landing_page_enabled;
    portillia_admin_lease_t *leases;
    size_t leases_count;
    portillia_admin_udp_settings_response_t udp;
    portillia_admin_tcp_port_settings_response_t tcp_port;
} portillia_admin_snapshot_response_t;

/* ---------- Lifecycle helpers ---------- */

void portillia_identity_init(portillia_identity_t *id);
void portillia_identity_cleanup(portillia_identity_t *id);
void portillia_identity_copy(portillia_identity_t *dst, const portillia_identity_t *src);

void portillia_relay_identity_init(portillia_relay_identity_t *id);
void portillia_relay_identity_cleanup(portillia_relay_identity_t *id);

void portillia_lease_metadata_init(portillia_lease_metadata_t *m);
void portillia_lease_metadata_cleanup(portillia_lease_metadata_t *m);
void portillia_lease_metadata_copy(portillia_lease_metadata_t *dst, const portillia_lease_metadata_t *src);

void portillia_lease_init(portillia_lease_t *l);
void portillia_lease_cleanup(portillia_lease_t *l);
void portillia_lease_copy(portillia_lease_t *dst, const portillia_lease_t *src);

void portillia_relay_descriptor_init(portillia_relay_descriptor_t *d);
void portillia_relay_descriptor_cleanup(portillia_relay_descriptor_t *d);
void portillia_relay_descriptor_copy(portillia_relay_descriptor_t *dst, const portillia_relay_descriptor_t *src);

void portillia_datagram_frame_init(portillia_datagram_frame_t *f);
void portillia_datagram_frame_cleanup(portillia_datagram_frame_t *f);
void portillia_datagram_frame_copy(portillia_datagram_frame_t *dst, const portillia_datagram_frame_t *src);

void portillia_hop_route_init(portillia_hop_route_t *r);
void portillia_hop_route_cleanup(portillia_hop_route_t *r);
void portillia_hop_route_copy(portillia_hop_route_t *dst, const portillia_hop_route_t *src);

void portillia_agent_relay_status_init(portillia_agent_relay_status_t *s);
void portillia_agent_relay_status_cleanup(portillia_agent_relay_status_t *s);

void portillia_agent_tunnel_status_init(portillia_agent_tunnel_status_t *s);
void portillia_agent_tunnel_status_cleanup(portillia_agent_tunnel_status_t *s);

void portillia_net_conn_init(portillia_net_conn_t *c);
void portillia_net_conn_cleanup(portillia_net_conn_t *c);

void portillia_discovery_response_init(portillia_discovery_response_t *r);
void portillia_discovery_response_cleanup(portillia_discovery_response_t *r);
void portillia_domain_response_cleanup(portillia_domain_response_t *r);
void portillia_register_challenge_response_cleanup(portillia_register_challenge_response_t *r);
void portillia_register_response_cleanup(portillia_register_response_t *r);
void portillia_renew_response_cleanup(portillia_renew_response_t *r);

#ifdef __cplusplus
}
#endif

#endif /* PORTILLIA_TYPES_H */
