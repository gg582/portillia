/** @file types.h
 * @brief Core Portillia data structures.
 */
#ifndef PORTILLIA_TYPES_H
#define PORTILLIA_TYPES_H

#include <cwist/core/sstring/sstring.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define PORTILLIA_RELEASE_VERSION "v2.1.8"
#define PORTILLIA_SDK_VERSION "6"
#define PORTILLIA_DISCOVERY_VERSION "7"

/**
 * @struct portillia_identity
 * @brief Represents a unique service identity in the portal network.
 */
typedef struct portillia_identity {
    cwist_sstring *name;        /**< Name label */
    cwist_sstring *address;     /**< Unique network address */
    cwist_sstring *public_key;  /**< Ed25519 public key */
    cwist_sstring *private_key; /**< Ed25519 private key */
} portillia_identity;

/**
 * @struct portillia_lease_metadata
 * @brief Metadata for a public service lease.
 */
typedef struct portillia_lease_metadata {
    cwist_sstring *description; /**< Service description */
    cwist_sstring *owner;       /**< Owner contact/identifier */
    cwist_sstring *thumbnail;   /**< Service thumbnail URL */
    cwist_sstring **tags;       /**< Array of searchable tags */
    size_t tags_count;          /**< Number of tags */
    bool hide;                  /**< Hide from public listings */
} portillia_lease_metadata;

/**
 * @struct portillia_lease
 * @brief Active lease information.
 */
typedef struct portillia_lease {
    cwist_sstring *name;        /**< Lease name */
    time_t expires_at;          /**< Expiration timestamp */
    time_t first_seen_at;       /**< Creation timestamp */
    time_t last_seen_at;        /**< Last heartbeat timestamp */
    cwist_sstring *hostname;    /**< Public hostname */
    bool udp_enabled;           /**< Is UDP supported */
    bool tcp_enabled;           /**< Is raw TCP supported */
    cwist_sstring *tcp_addr;    /**< Public TCP port address */
    portillia_lease_metadata metadata; /**< Associated lease metadata */
    int ready;                  /**< Readiness status flag */
    
    // Multi-hop fields
    cwist_sstring *hop_token;             /**< Token to match for this hop */
    cwist_sstring *hop_next_overlay_ipv4; /**< Next hop overlay address */
    cwist_sstring *hop_next_token;        /**< Token to send to next hop */
} portillia_lease;

/**
 * @struct portillia_relay_descriptor
 * @brief Relay node capabilities and registration info.
 */
typedef struct portillia_relay_descriptor {
    cwist_sstring *address;     /**< Relay public address */
    cwist_sstring *version;     /**< Relay binary version */
    time_t issued_at;           /**< Descriptor issuance */
    time_t expires_at;          /**< Descriptor validity */
    cwist_sstring *api_https_addr; /**< HTTPS API endpoint */
    cwist_sstring *wireguard_public_key; /**< Relay WG public key */
    int wireguard_port;         /**< WG listen port */
    bool supports_overlay;      /**< Supports overlay routing */
    bool supports_udp;          /**< Supports UDP relaying */
    bool supports_tcp;          /**< Supports raw TCP relaying */
    int64_t active_connections; /**< Concurrent connection count */
    double tcp_bps;             /**< Throughput in bits per second */
    cwist_sstring *signature;   /**< Descriptor signature */
} portillia_relay_descriptor;

/**
 * @struct portillia_datagram_frame
 * @brief Encapsulates a relayed datagram.
 */
typedef struct portillia_datagram_frame {
    uint32_t flow_id;           /**< Unique flow identifier */
    uint8_t *payload;           /**< Datagram content */
    size_t payload_len;         /**< Content length */
    cwist_sstring *address;     /**< Destination address */
    cwist_sstring *relay_url;   /**< Originating relay */
    cwist_sstring *udp_addr;    /**< Source UDP address */
} portillia_datagram_frame;

#ifndef CWIST_SUCCESS
#define CWIST_SUCCESS 0
#endif
#ifndef CWIST_FAILURE
#define CWIST_FAILURE -1
#endif

// Identity functions
portillia_identity *portillia_identity_create(void);
void portillia_identity_destroy(portillia_identity *id);
portillia_identity *portillia_identity_copy(const portillia_identity *id);

// Metadata functions
void portillia_lease_metadata_init(portillia_lease_metadata *m);
void portillia_lease_metadata_cleanup(portillia_lease_metadata *m);
void portillia_lease_metadata_copy(portillia_lease_metadata *dst, const portillia_lease_metadata *src);

// Lease functions
portillia_lease *portillia_lease_create(void);
void portillia_lease_destroy(portillia_lease *l);

#endif // PORTILLIA_TYPES_H