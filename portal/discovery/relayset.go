package discovery

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// RelaySet owns the shared relay discovery view: configured bootstrap relay URLs,
// the latest validated descriptor seen for each relay, and local runtime state
// such as ban/reachability/failure tracking and observed discovery RTT.
type RelaySet struct {
	mu     sync.RWMutex
	relays map[string]RelayState
	policy RelayPolicy
}

func NewRelaySet(bootstrapRelayURLs []string) (*RelaySet, error) {
	set := &RelaySet{
		relays: make(map[string]RelayState),
		policy: DefaultRelayPolicy{},
	}
	if err := set.SetBootstrapRelayURLs(bootstrapRelayURLs); err != nil {
		return nil, err
	}
	return set, nil
}

func (s *RelaySet) SetRelayPolicy(policy RelayPolicy) {
	if policy == nil {
		policy = DefaultRelayPolicy{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = policy
}

func (s *RelaySet) SetBootstrapRelayURLs(inputs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	keep := make(map[string]struct{}, len(inputs))
	for _, relayURL := range inputs {
		keep[relayURL] = struct{}{}
	}

	for key, state := range s.relays {
		_, bootstrap := keep[key]
		state.Bootstrap = bootstrap
		if !state.Bootstrap && !state.hasDescriptor() && !state.Banned && state.consecutiveFailures == 0 {
			delete(s.relays, key)
			continue
		}

		s.relays[key] = state
	}

	for _, relayURL := range inputs {
		if _, ok := s.relays[relayURL]; ok {
			continue
		}

		state := newRelayStateFromURL(relayURL)
		state.Bootstrap = true
		s.relays[relayURL] = state
	}
	return nil
}

func (s *RelaySet) ActiveRelays() []RelayState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.policy.SelectActive(s.relayStatesLocked())
}

func (s *RelaySet) PriorityRelays(clientState ClientState) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.policy.SelectPriority(s.relayStatesLocked(), clientState)
}

func (s *RelaySet) OverlayPeerStates() []RelayState {
	s.mu.RLock()
	states := s.relayStatesLocked()
	s.mu.RUnlock()

	now := time.Now().UTC()
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		if !state.discoverable(now) || !state.Descriptor.SupportsOverlayPeer {
			continue
		}
		if state.Descriptor.WireGuardPublicKey == "" ||
			state.Descriptor.WireGuardEndpoint == "" ||
			state.Descriptor.OverlayIPv4 == "" {
			continue
		}
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) Descriptors() []types.RelayDescriptor {
	s.mu.RLock()
	states := s.relayStatesLocked()
	s.mu.RUnlock()

	now := time.Now().UTC()
	out := make([]types.RelayDescriptor, 0, len(states))
	for _, state := range states {
		if !state.hasDescriptor() || !state.Descriptor.ExpiresAt.After(now) || !state.Descriptor.Discovery {
			continue
		}
		out = append(out, state.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) ServeDiscovery(w http.ResponseWriter, r *http.Request, local ...types.RelayDescriptor) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}

	known := s.Descriptors()
	relays := make([]types.RelayDescriptor, 0, len(local)+len(known))
	seen := make(map[string]struct{}, len(local)+len(known))
	add := func(descriptor types.RelayDescriptor) {
		relayURL := descriptor.APIHTTPSAddr
		if relayURL == "" {
			return
		}
		if _, ok := seen[relayURL]; ok {
			return
		}
		seen[relayURL] = struct{}{}
		relays = append(relays, descriptor)
	}

	for _, descriptor := range local {
		add(descriptor)
	}
	for _, descriptor := range known {
		add(descriptor)
	}

	utils.WriteAPIData(w, http.StatusOK, types.DiscoveryResponse{
		ProtocolVersion: types.ProtocolVersion,
		GeneratedAt:     time.Now().UTC(),
		Relays:          relays,
	})
}

func (s *RelaySet) relayStatesLocked() []RelayState {
	out := make([]RelayState, 0, len(s.relays))
	for _, state := range s.relays {
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Descriptor.APIHTTPSAddr < out[j].Descriptor.APIHTTPSAddr
	})
	return out
}

func (s *RelaySet) BanRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		state = newRelayStateFromURL(relayURL)
	}
	state = s.policy.OnBanned(state)
	s.relays[relayURL] = state
}

func (s *RelaySet) ApplyRelayDiscoveryResponse(targetURL string, resp types.DiscoveryResponse, now time.Time) (relaySetChanged bool, err error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	if resp.ProtocolVersion != types.ProtocolVersion {
		return false, fmt.Errorf("relay protocol version mismatch: relay=%q client=%q", resp.ProtocolVersion, types.ProtocolVersion)
	}
	authoritative := targetURL != ""

	s.mu.Lock()
	defer s.mu.Unlock()

	discoveredByURL := make(map[string]RelayState, len(resp.Relays))
	discoveredOrder := make([]string, 0, len(resp.Relays))
	targetFound := false
	for _, descriptor := range resp.Relays {
		relayState, err := newRelayState(descriptor, now)
		if err != nil {
			continue
		}
		relayURL := relayState.Descriptor.APIHTTPSAddr
		if relayURL == "" {
			continue
		}
		if authoritative && relayURL == targetURL {
			targetFound = true
		}
		if _, ok := discoveredByURL[relayURL]; !ok {
			discoveredOrder = append(discoveredOrder, relayURL)
		}
		discoveredByURL[relayURL] = relayState
	}

	if authoritative && !targetFound {
		return false, errors.New("target relay descriptor missing from relays")
	}

	for _, relayURL := range discoveredOrder {
		record := discoveredByURL[relayURL]
		existingAtURL, hasExistingAtURL := s.relays[relayURL]
		record.Bootstrap = record.Bootstrap || existingAtURL.Bootstrap
		record.Reachable = record.Reachable || existingAtURL.Reachable
		record.Confirmed = record.Confirmed || existingAtURL.Confirmed
		record.Banned = record.Banned || existingAtURL.Banned
		if record.consecutiveFailures < existingAtURL.consecutiveFailures {
			record.consecutiveFailures = existingAtURL.consecutiveFailures
		}
		if record.DiscoveryRTTAt.IsZero() || (!existingAtURL.DiscoveryRTTAt.IsZero() && existingAtURL.DiscoveryRTTAt.After(record.DiscoveryRTTAt)) {
			record.DiscoveryRTT = existingAtURL.DiscoveryRTT
			record.DiscoveryRTTAt = existingAtURL.DiscoveryRTTAt
		}

		if authoritative && relayURL == targetURL {
			record = s.policy.OnConfirmed(record)
		} else {
			record = s.policy.OnHinted(record)
		}

		s.relays[relayURL] = record

		if !hasExistingAtURL || !reflect.DeepEqual(existingAtURL, record) {
			relaySetChanged = true
		}
	}
	return relaySetChanged, nil
}

func (s *RelaySet) RecordDiscoveryRTT(relayURL string, rtt time.Duration, measuredAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}

	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = measuredAt
	s.relays[relayURL] = state
}

func (s *RelaySet) RecordRelayFailure(relayURL string, err error, recoveryFailures int) (expired bool, expireReason string, consecutiveFailures int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return false, "", 0
	}
	state, expired, expireReason = s.policy.OnFailure(state, err, recoveryFailures)
	s.relays[relayURL] = state
	return expired, expireReason, state.consecutiveFailures
}
