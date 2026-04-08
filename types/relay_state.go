package types

import "time"

// RelayState captures the last-known descriptor and local state for a relay
// observed through discovery.
type RelayState struct {
	Descriptor          RelayDescriptor `json:"descriptor"`
	Bootstrap           bool            `json:"bootstrap,omitempty"`
	Advertised          bool            `json:"advertised,omitempty"`
	Expired             bool            `json:"expired,omitempty"`
	Banned              bool            `json:"banned,omitempty"`
	FirstSeenAt         time.Time       `json:"first_seen_at"`
	LastSeenAt          time.Time       `json:"last_seen_at"`
	ConsecutiveFailures int             `json:"consecutive_failures,omitempty"`
}
