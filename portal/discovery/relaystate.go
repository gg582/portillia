package discovery

import (
	"errors"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type RelayState struct {
	Descriptor     types.RelayDescriptor
	Bootstrap      bool
	Reachable      bool
	Confirmed      bool
	Banned         bool
	LastSeenAt     time.Time
	DiscoveryRTT   time.Duration
	DiscoveryRTTAt time.Time

	consecutiveFailures int
}

type ClientState struct {
	ActiveRelayURLs   []string
	ExplicitRelayURLs []string
	MaxActiveRelays   int
	RequireUDP        bool
	RequireTCP        bool
}

func newRelayState(desc types.RelayDescriptor, seenAt time.Time) (RelayState, error) {
	state := RelayState{
		Descriptor: desc,
	}
	if seenAt.IsZero() {
		return state, nil
	}

	seenAt = seenAt.UTC()
	normalized, err := utils.NormalizeDescriptor(desc)
	if err != nil {
		return RelayState{}, err
	}
	if normalized.ExpiresAt.Before(seenAt) {
		return RelayState{}, errors.New("descriptor expired")
	}

	state.Descriptor = normalized
	state.LastSeenAt = seenAt
	return state, nil
}

func newRelayStateFromURL(relayURL string) RelayState {
	return RelayState{
		Descriptor: types.RelayDescriptor{
			Identity: types.Identity{
				Name: utils.PortalRootHost(relayURL),
			},
			RelayID:      relayURL,
			APIHTTPSAddr: relayURL,
		},
	}
}

func (state RelayState) hasDescriptor() bool {
	return !state.LastSeenAt.IsZero()
}

func (state RelayState) discoverable(now time.Time) bool {
	if state.Banned {
		return false
	}
	if !state.hasDescriptor() {
		return state.Bootstrap
	}
	if !state.Bootstrap && !state.Reachable {
		return false
	}
	if !state.Descriptor.ExpiresAt.After(now) {
		return false
	}
	return true
}

func (state RelayState) Equal(other RelayState) bool {
	stateKey := state.Descriptor.Key()
	otherKey := other.Descriptor.Key()
	if stateKey != "" && otherKey != "" && stateKey == otherKey {
		return true
	}

	stateURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
	otherURL := strings.TrimSpace(other.Descriptor.APIHTTPSAddr)
	return stateURL != "" && otherURL != "" && stateURL == otherURL
}
