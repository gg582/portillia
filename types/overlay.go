package types

// DesiredPeer describes a WireGuard peer that should be programmed into the
// local runtime.
type DesiredPeer struct {
	RelayID            string   `json:"relay_id"`
	WireGuardPublicKey string   `json:"wireguard_public_key"`
	WireGuardEndpoint  string   `json:"wireguard_endpoint"`
	AllowedIPs         []string `json:"allowed_ips,omitempty"`
}
