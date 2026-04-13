package types

import (
	"strings"
	"time"
)

const (
	IdentityKeySeparator       = ":"
	RelayIdentityFilename      = "identity.json"
	RelayAdminSettingsFilename = "admin_settings.json"
)

type Identity struct {
	Name       string `json:"name,omitempty"`
	Address    string `json:"address,omitempty"`
	PublicKey  string `json:"-"`
	PrivateKey string `json:"-"`
}

func (i Identity) Copy() Identity {
	return Identity{
		Name:       i.Name,
		Address:    i.Address,
		PublicKey:  i.PublicKey,
		PrivateKey: i.PrivateKey,
	}
}

type RelayIdentity struct {
	Identity
	AdminSecretKey      string `json:"-"`
	WireGuardPublicKey  string `json:"-"`
	WireGuardPrivateKey string `json:"-"`
}

func (i RelayIdentity) Copy() RelayIdentity {
	return RelayIdentity{
		Identity:            i.Identity.Copy(),
		AdminSecretKey:      i.AdminSecretKey,
		WireGuardPublicKey:  i.WireGuardPublicKey,
		WireGuardPrivateKey: i.WireGuardPrivateKey,
	}
}

func (i RelayIdentity) Base() Identity {
	return i.Identity.Copy()
}

func (i Identity) Key() string {
	name := strings.TrimSpace(strings.ToLower(i.Name))
	address := strings.TrimSpace(strings.ToLower(i.Address))
	if name == "" && address == "" {
		return ""
	}
	return name + IdentityKeySeparator + address
}

type LeaseMetadata struct {
	Description string   `json:"description,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Thumbnail   string   `json:"thumbnail,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Hide        bool     `json:"hide,omitempty"`
}

func (m LeaseMetadata) Copy() LeaseMetadata {
	return LeaseMetadata{
		Description: m.Description,
		Owner:       m.Owner,
		Thumbnail:   m.Thumbnail,
		Tags:        append([]string(nil), m.Tags...),
		Hide:        m.Hide,
	}
}

type Lease struct {
	Name        string `json:"name,omitempty"`
	ExpiresAt   time.Time
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	Hostname    string
	UDPEnabled  bool
	TCPEnabled  bool
	TCPAddr     string
	Metadata    LeaseMetadata
	Ready       int
}

type AdminLease struct {
	Lease
	IdentityKey string `json:"identity_key,omitempty"`
	Address     string `json:"address,omitempty"`
	BPS         int64
	ClientIP    string
	ReportedIP  string
	IsApproved  bool
	IsBanned    bool
	IsDenied    bool
	IsIPBanned  bool
}

type RelayDescriptor struct {
	Identity

	RelayID             string    `json:"relay_id,omitempty"`
	OwnerAddress        string    `json:"owner_address,omitempty"`
	Version             uint32    `json:"version"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	APIHTTPSAddr        string    `json:"api_https_addr"`
	IngressTLSAddr      string    `json:"ingress_tls_addr,omitempty"`
	WireGuardPublicKey  string    `json:"wireguard_public_key,omitempty"`
	WireGuardEndpoint   string    `json:"wireguard_endpoint,omitempty"`
	OverlayIPv4         string    `json:"overlay_ipv4,omitempty"`
	OverlayCIDRs        []string  `json:"overlay_cidrs,omitempty"`
	Discovery           bool      `json:"discovery,omitempty"`
	SupportsUDP         bool      `json:"supports_udp,omitempty"`
	SupportsTCP         bool      `json:"supports_tcp,omitempty"`
	SupportsOverlayPeer bool      `json:"supports_overlay_peer,omitempty"`
	Load                float64   `json:"load,omitempty"`
	LoadScore           float64   `json:"load_score,omitempty"`
	LastUpdated         int64     `json:"last_updated,omitempty"`
}
