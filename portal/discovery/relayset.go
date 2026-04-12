package discovery

import (
	"errors"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// RelaySet owns the shared relay discovery view: configured bootstrap relay URLs,
// the latest validated descriptor seen for each relay, and local runtime state
// such as ban/reachability/failure tracking.
type RelaySet struct {
	mu             sync.RWMutex
	knownRelayURLs []string
	relays         map[string]RelayState
	policy         RelayPolicy
	selfRelayKey   string
	selfRelayURL   string
}

func NewRelaySet(identity types.Identity, relayURL string, bootstrapRelayURLs []string) (*RelaySet, error) {
	if relayURL != "" {
		normalized, err := utils.NormalizeRelayURL(relayURL)
		if err != nil {
			return nil, err
		}
		relayURL = normalized
	}

	set := &RelaySet{
		relays:       make(map[string]RelayState),
		policy:       DefaultRelayPolicy{},
		selfRelayKey: identity.Key(),
		selfRelayURL: relayURL,
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
	normalized, err := utils.NormalizeRelayURLs(inputs...)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := utils.RemoveRelayURL(normalized, s.selfRelayURL)

	keep := make(map[string]struct{}, len(filtered))
	for _, relayURL := range filtered {
		keep[relayURL] = struct{}{}
	}

	for _, relayURL := range s.knownRelayURLs {
		if _, ok := keep[relayURL]; ok {
			continue
		}
		state := s.relays[relayURL]
		if state.hasDescriptor() {
			continue
		}
		if !s.policy.KeepState(state) {
			delete(s.relays, relayURL)
		}
	}

	s.knownRelayURLs = append([]string(nil), filtered...)
	return nil
}

func (s *RelaySet) relayURLForKeyLocked(relayKey string) string {
	if relayKey == "" {
		return ""
	}
	for relayURL, state := range s.relays {
		if state.hasDescriptor() && state.Descriptor.Key() == relayKey {
			return relayURL
		}
	}
	return ""
}

func (s *RelaySet) RelayStates() []RelayState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	states := s.relayStatesLocked()
	for i := range states {
		states[i] = s.policy.Decide(states[i])
	}
	return states
}

func (s *RelaySet) ActiveRelays() []RelayState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	states := s.relayStatesLocked()
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		state = s.policy.Decide(state)
		if state.Active && state.Descriptor.APIHTTPSAddr != "" {
			out = append(out, state)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) relayStatesLocked() []RelayState {
	out := make([]RelayState, 0, len(s.knownRelayURLs)+len(s.relays))
	seen := make(map[string]struct{}, len(s.knownRelayURLs)+len(s.relays))

	for _, relayURL := range s.knownRelayURLs {
		if relayURL == "" {
			continue
		}
		if _, ok := seen[relayURL]; ok {
			continue
		}
		seen[relayURL] = struct{}{}

		state, ok := s.relays[relayURL]
		if !ok {
			state = newRelayHintState(relayURL)
		}
		if selfRelay(state, s.selfRelayKey, s.selfRelayURL) {
			continue
		}
		state.Bootstrap = true
		out = append(out, state)
	}

	descriptorStates := make([]RelayState, 0, len(s.relays))
	for relayURL, record := range s.relays {
		if !record.hasDescriptor() {
			continue
		}
		relayURL = strings.TrimSpace(record.Descriptor.APIHTTPSAddr)
		if relayURL == "" {
			continue
		}
		if selfRelay(record, s.selfRelayKey, s.selfRelayURL) {
			continue
		}
		if _, ok := seen[relayURL]; ok {
			continue
		}

		record.Bootstrap = slices.Contains(s.knownRelayURLs, relayURL)
		descriptorStates = append(descriptorStates, record)
	}
	sort.Slice(descriptorStates, func(i, j int) bool {
		return descriptorStates[i].Descriptor.APIHTTPSAddr < descriptorStates[j].Descriptor.APIHTTPSAddr
	})
	out = append(out, descriptorStates...)

	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) AdvertisedDescriptors() []types.RelayDescriptor {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.policy.AdvertisedDescriptors(s.relayStatesLocked())
}

func (s *RelaySet) BanRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return
	}

	state := s.relays[relayURL]
	if state.Descriptor.APIHTTPSAddr == "" {
		state = newRelayHintState(relayURL)
	}
	state = s.policy.OnBanned(state)
	s.relays[relayURL] = state
}

func (s *RelaySet) storeDescriptorLocked(state RelayState, policy RelayPolicy) (bool, bool, error) {
	desc := state.Descriptor
	relayKey := desc.Key()
	if relayKey == "" {
		return false, false, errors.New("descriptor identity is required")
	}
	if existing := s.relays[desc.APIHTTPSAddr]; existing.hasDescriptor() && existing.Descriptor.Key() != relayKey {
		return false, false, errors.New("descriptor identity does not match known relay url")
	}

	previousURL := s.relayURLForKeyLocked(relayKey)
	record := s.relays[desc.APIHTTPSAddr]
	previousDescriptor := record.Descriptor
	if previousURL != "" && previousURL != desc.APIHTTPSAddr {
		previous := s.relays[previousURL]
		previousDescriptor = previous.Descriptor
		if !policy.KeepState(record) {
			record.Status = previous.Status
			record.consecutiveFailures = previous.consecutiveFailures
		}
		delete(s.relays, previousURL)
	}

	added := previousURL == ""
	if !policy.KeepState(record) {
		record = state
	} else {
		if record.FirstSeenAt.IsZero() {
			record.FirstSeenAt = state.FirstSeenAt
		}
		record.Descriptor = desc
		record.LastSeenAt = state.LastSeenAt
	}
	s.relays[desc.APIHTTPSAddr] = record

	changed := added || !reflect.DeepEqual(previousDescriptor, desc)
	return added, changed, nil
}

func (s *RelaySet) ApplyRelayDiscoveryResponse(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) (relaySetChanged bool, err error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	policy := s.policy

	selfState, relayStates, err := policy.DiscoveryStates(targetIdentity, targetURL, s.selfRelayKey, s.selfRelayURL, resp, now)
	if err != nil {
		return false, err
	}

	apply := func(state RelayState, advertise bool) error {
		desc := state.Descriptor
		added, descriptorChanged, err := s.storeDescriptorLocked(state, policy)
		if err != nil {
			return err
		}

		storedState := s.relays[desc.APIHTTPSAddr]
		previousState := storedState
		storedState = policy.OnDiscovered(storedState, advertise)
		s.relays[desc.APIHTTPSAddr] = storedState

		changed := added || descriptorChanged || !reflect.DeepEqual(previousState, s.relays[desc.APIHTTPSAddr])
		if changed {
			relaySetChanged = true
		}
		return nil
	}

	if err := apply(selfState, true); err != nil {
		return false, err
	}
	for _, relayState := range relayStates {
		if err := apply(relayState, false); err != nil {
			return false, err
		}
	}
	return relaySetChanged, nil
}

func (s *RelaySet) RecordDiscoveryFailure(identity types.Identity, relayURL string, err error, recoveryFailures int) (expired bool, expireReason string, consecutiveFailures int) {
	relayKey := identity.Key()
	if relayKey == "" {
		return false, "", 0
	}
	relayURL = strings.TrimSpace(relayURL)

	s.mu.Lock()
	defer s.mu.Unlock()

	if relayURL == "" || s.relays[relayURL].Descriptor.Key() != relayKey {
		relayURL = s.relayURLForKeyLocked(relayKey)
	}
	if relayURL == "" {
		return false, "", 0
	}

	state, ok := s.relays[relayURL]
	if !ok {
		return false, "", 0
	}
	state, expired, expireReason = s.policy.OnFailure(state, err, recoveryFailures)
	s.relays[relayURL] = state
	return expired, expireReason, state.consecutiveFailures
}
