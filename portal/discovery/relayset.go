package discovery

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
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
	self   RelayState
}

func NewRelaySet(identity types.Identity, relayURL string, bootstrapRelayURLs []string) (*RelaySet, error) {
	set := &RelaySet{
		relays: make(map[string]RelayState),
		policy: DefaultRelayPolicy{},
		self: RelayState{
			Descriptor: types.RelayDescriptor{
				Identity:     identity,
				RelayID:      relayURL,
				APIHTTPSAddr: relayURL,
			},
		},
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

	filtered := utils.RemoveRelayURL(inputs, s.self.Descriptor.APIHTTPSAddr)
	keep := make(map[string]struct{}, len(filtered))
	for _, relayURL := range filtered {
		keep[relayURL] = struct{}{}
	}

	seen := make(map[string]struct{}, len(filtered))
	for key, state := range s.relays {
		if state.Equal(s.self) {
			delete(s.relays, key)
			continue
		}

		_, bootstrap := keep[key]
		state.Bootstrap = bootstrap
		if !state.Bootstrap &&
			!state.hasDescriptor() &&
			!state.Banned &&
			state.consecutiveFailures == 0 {
			delete(s.relays, key)
			continue
		}

		s.relays[key] = state
		if bootstrap {
			seen[key] = struct{}{}
		}
	}

	for _, relayURL := range filtered {
		if _, ok := seen[relayURL]; ok {
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

func (s *RelaySet) ConfirmedDescriptors() []types.RelayDescriptor {
	s.mu.RLock()
	defer s.mu.RUnlock()

	states := s.policy.SelectConfirmed(s.relayStatesLocked())
	out := make([]types.RelayDescriptor, 0, len(states))
	for _, state := range states {
		out = append(out, state.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
	if state.Equal(s.self) {
		delete(s.relays, relayURL)
		return
	}
	state = s.policy.OnBanned(state)
	s.relays[relayURL] = state
}

func (s *RelaySet) applyDiscoveredStateLocked(state RelayState, confirmed bool) (bool, error) {
	relayURL := state.Descriptor.APIHTTPSAddr
	relayKey := state.Descriptor.Key()

	previousState, hadPrevious := s.relays[relayURL]
	record := previousState

	if hadPrevious && record.hasDescriptor() && record.Descriptor.Key() != relayKey {
		return false, errors.New("descriptor identity does not match known relay url")
	}

	previousURL := ""
	for url, existing := range s.relays {
		if url == relayURL || !existing.hasDescriptor() || existing.Descriptor.Key() != relayKey {
			continue
		}
		previousURL = url
		if !record.hasDescriptor() &&
			!record.Banned &&
			record.consecutiveFailures == 0 {
			record.Reachable = existing.Reachable
			record.Confirmed = existing.Confirmed
			record.Banned = existing.Banned
			record.DiscoveryRTT = existing.DiscoveryRTT
			record.DiscoveryRTTAt = existing.DiscoveryRTTAt
			record.consecutiveFailures = existing.consecutiveFailures
		}
		break
	}

	if !record.hasDescriptor() &&
		!record.Banned &&
		record.consecutiveFailures == 0 {
		record = state
	} else {
		record.Descriptor = state.Descriptor
		record.LastSeenAt = state.LastSeenAt
	}

	if confirmed {
		record = s.policy.OnConfirmed(record)
	} else {
		record = s.policy.OnHinted(record)
	}

	if previousURL != "" {
		delete(s.relays, previousURL)
	}
	s.relays[relayURL] = record

	return !hadPrevious || previousURL != "" || !reflect.DeepEqual(previousState, record), nil
}

func (s *RelaySet) ApplyRelayDiscoveryResponse(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) (relaySetChanged bool, err error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if resp.ProtocolVersion != types.ProtocolVersion {
		return false, fmt.Errorf("relay protocol version mismatch: relay=%q client=%q", resp.ProtocolVersion, types.ProtocolVersion)
	}

	selfState, err := newRelayState(resp.Self, now)
	if err != nil {
		return false, err
	}
	if selfState.Equal(s.self) {
		return false, nil
	}
	if strings.TrimSpace(targetIdentity.Name) == "" && strings.TrimSpace(targetIdentity.Address) == "" {
		return false, errors.New("target relay identity is required")
	}
	if targetName := strings.TrimSpace(targetIdentity.Name); targetName != "" {
		if selfState.Descriptor.Name != utils.NormalizeHostname(targetName) {
			return false, errors.New("descriptor name does not match target relay")
		}
	}
	if targetAddress := strings.TrimSpace(targetIdentity.Address); targetAddress != "" {
		normalizedTargetAddress, err := utils.NormalizeEVMAddress(targetAddress)
		if err != nil {
			return false, err
		}
		if selfState.Descriptor.Address != normalizedTargetAddress {
			return false, errors.New("descriptor address does not match target relay")
		}
	}
	if targetURL != "" && selfState.Descriptor.APIHTTPSAddr != strings.TrimSpace(targetURL) {
		return false, errors.New("descriptor api_https_addr does not match target url")
	}
	changed, err := s.applyDiscoveredStateLocked(selfState, true)
	if err != nil {
		return false, err
	}
	relaySetChanged = relaySetChanged || changed

	seen := map[string]struct{}{selfState.Descriptor.Key(): {}}
	for _, descriptor := range resp.Relays {
		relayState, err := newRelayState(descriptor, now)
		if err != nil {
			continue
		}
		if relayState.Equal(s.self) {
			continue
		}
		relayKey := relayState.Descriptor.Key()
		if _, ok := seen[relayKey]; ok {
			continue
		}
		seen[relayKey] = struct{}{}

		changed, err := s.applyDiscoveredStateLocked(relayState, false)
		if err != nil {
			return false, err
		}
		relaySetChanged = relaySetChanged || changed
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

func (s *RelaySet) recordRelayFailureLocked(relayURL string, state RelayState, err error, recoveryFailures int) (expired bool, expireReason string, consecutiveFailures int) {
	state, expired, expireReason = s.policy.OnFailure(state, err, recoveryFailures)
	s.relays[relayURL] = state
	return expired, expireReason, state.consecutiveFailures
}

func (s *RelaySet) RecordRelayFailure(relayURL string, err error, recoveryFailures int) (expired bool, expireReason string, consecutiveFailures int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return false, "", 0
	}
	return s.recordRelayFailureLocked(relayURL, state, err, recoveryFailures)
}

func (s *RelaySet) RecordDiscoveryFailure(identity types.Identity, relayURL string, err error, recoveryFailures int) (expired bool, expireReason string, consecutiveFailures int) {
	relayKey := identity.Key()
	if relayKey == "" {
		return false, "", 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if ok && state.hasDescriptor() && state.Descriptor.Key() != relayKey {
		ok = false
	}
	if !ok {
		for url, existing := range s.relays {
			if !existing.hasDescriptor() || existing.Descriptor.Key() != relayKey {
				continue
			}
			relayURL = url
			state = existing
			ok = true
			break
		}
	}
	if !ok {
		return false, "", 0
	}
	return s.recordRelayFailureLocked(relayURL, state, err, recoveryFailures)
}
