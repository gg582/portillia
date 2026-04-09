package discovery

import (
	"errors"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type relayStatus uint8

const (
	relayStatusHinted relayStatus = iota
	relayStatusConfirmed
	relayStatusExpired
)

// RelayState is the single relay shape shared by discovery storage and overlay sync.
// Package-private fields are internal-only local state.
type RelayState struct {
	Descriptor          types.RelayDescriptor
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	Banned              bool
	Expired             bool
	status              relayStatus
	consecutiveFailures int
}

func (s RelayState) isDefaultLocalState() bool {
	return !s.Banned && s.status == relayStatusHinted && s.consecutiveFailures == 0
}

// RelaySet owns the shared relay discovery view: configured bootstrap relay URLs,
// the latest validated descriptor seen for each relay, and local runtime state
// such as ban/reachability/failure tracking.
type RelaySet struct {
	mu             sync.RWMutex
	knownRelayURLs []string
	relayKeysByURL map[string]string
	relays         map[string]RelayState
	localByURL     map[string]RelayState
	selfRelayKey   string
	selfRelayURL   string
}

type relayDescriptorProjection struct {
	state     RelayState
	relayURL  string
	bootstrap bool
}

func NewRelaySet(identity types.Identity, relayURL string, bootstrapRelayURLs []string) (*RelaySet, error) {
	set := &RelaySet{
		relayKeysByURL: make(map[string]string),
		relays:         make(map[string]RelayState),
		localByURL:     make(map[string]RelayState),
	}
	if err := set.SetSelfRelay(identity, relayURL); err != nil {
		return nil, err
	}
	if err := set.SetBootstrapRelayURLs(bootstrapRelayURLs); err != nil {
		return nil, err
	}
	return set, nil
}

func relayExpiredAt(state RelayState, now time.Time) bool {
	if state.status == relayStatusExpired {
		return true
	}
	if state.Descriptor.ExpiresAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !state.Descriptor.ExpiresAt.After(now)
}

func (s *RelaySet) isSelfRelayURLLocked(relayURL string) bool {
	relayURL = strings.TrimSpace(relayURL)
	return relayURL != "" && s.selfRelayURL != "" && relayURL == s.selfRelayURL
}

func (s *RelaySet) isSelfRelayDescriptorLocked(desc types.RelayDescriptor) bool {
	if relayKey := desc.Key(); relayKey != "" && s.selfRelayKey != "" && relayKey == s.selfRelayKey {
		return true
	}
	return s.isSelfRelayURLLocked(desc.APIHTTPSAddr)
}

func (s *RelaySet) storeLocalStateLocked(relayURL string, state RelayState) {
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return
	}
	if state.isDefaultLocalState() {
		delete(s.localByURL, relayURL)
		return
	}
	s.localByURL[relayURL] = state
}

func (s *RelaySet) SetSelfRelay(identity types.Identity, relayURL string) error {
	relayURL = strings.TrimSpace(relayURL)
	if relayURL != "" {
		normalized, err := utils.NormalizeRelayURL(relayURL)
		if err != nil {
			return err
		}
		relayURL = normalized
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.selfRelayKey = identity.Key()
	s.selfRelayURL = relayURL
	if s.selfRelayURL != "" {
		filtered := s.knownRelayURLs[:0]
		for _, knownRelayURL := range s.knownRelayURLs {
			if s.isSelfRelayURLLocked(knownRelayURL) {
				continue
			}
			filtered = append(filtered, knownRelayURL)
		}
		s.knownRelayURLs = filtered
		delete(s.localByURL, s.selfRelayURL)
		delete(s.relayKeysByURL, s.selfRelayURL)
	}
	if s.selfRelayKey != "" {
		if record, ok := s.relays[s.selfRelayKey]; ok {
			delete(s.localByURL, record.Descriptor.APIHTTPSAddr)
			delete(s.relayKeysByURL, record.Descriptor.APIHTTPSAddr)
		}
		delete(s.relays, s.selfRelayKey)
	}
	return nil
}

func (s *RelaySet) bootstrapRelayURLsLocked() []string {
	if len(s.knownRelayURLs) == 0 {
		return nil
	}

	out := make([]string, 0, len(s.knownRelayURLs))
	for _, relayURL := range s.knownRelayURLs {
		if s.isSelfRelayURLLocked(relayURL) || s.localByURL[relayURL].Banned {
			continue
		}
		out = append(out, relayURL)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) descriptorProjectionsLocked() []relayDescriptorProjection {
	if len(s.relays) == 0 {
		return nil
	}

	out := make([]relayDescriptorProjection, 0, len(s.relays))
	for _, record := range s.relays {
		if s.isSelfRelayDescriptorLocked(record.Descriptor) {
			continue
		}
		relayURL := strings.TrimSpace(record.Descriptor.APIHTTPSAddr)
		if relayURL == "" {
			continue
		}
		bootstrap := false
		if !s.isSelfRelayURLLocked(relayURL) {
			for _, candidate := range s.knownRelayURLs {
				if candidate == relayURL {
					bootstrap = true
					break
				}
			}
		}
		local := s.localByURL[relayURL]
		record.Banned = local.Banned
		record.status = local.status
		record.consecutiveFailures = local.consecutiveFailures
		out = append(out, relayDescriptorProjection{
			state:     record,
			relayURL:  relayURL,
			bootstrap: bootstrap,
		})
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].relayURL < out[j].relayURL
	})
	return out
}

func (s *RelaySet) ActiveRelayURLs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	bootstrapRelayURLs := s.bootstrapRelayURLsLocked()
	projections := s.descriptorProjectionsLocked()

	out := make([]string, 0, len(bootstrapRelayURLs)+len(projections))
	seen := make(map[string]struct{}, len(bootstrapRelayURLs)+len(projections))
	for _, relayURL := range bootstrapRelayURLs {
		if _, ok := seen[relayURL]; ok {
			continue
		}
		seen[relayURL] = struct{}{}
		out = append(out, relayURL)
	}
	for _, projection := range projections {
		if projection.state.Banned || projection.state.status != relayStatusConfirmed || relayExpiredAt(projection.state, now) {
			continue
		}
		if _, ok := seen[projection.relayURL]; ok {
			continue
		}
		seen[projection.relayURL] = struct{}{}
		out = append(out, projection.relayURL)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) BootstrapDescriptors() []types.RelayDescriptor {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bootstrapRelayURLs := s.bootstrapRelayURLsLocked()
	if len(bootstrapRelayURLs) == 0 {
		return nil
	}

	out := make([]types.RelayDescriptor, 0, len(bootstrapRelayURLs))
	for _, relayURL := range bootstrapRelayURLs {
		if relayKey, ok := s.relayKeysByURL[relayURL]; ok {
			if record, ok := s.relays[relayKey]; ok && record.Descriptor.APIHTTPSAddr != "" {
				out = append(out, record.Descriptor)
				continue
			}
		}
		out = append(out, types.RelayDescriptor{
			Identity: types.Identity{
				Name: utils.PortalRootHost(relayURL),
			},
			RelayID:      relayURL,
			APIHTTPSAddr: relayURL,
			Version:      1,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) BanRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return
	}

	state := s.localByURL[relayURL]
	state.Banned = true
	s.storeLocalStateLocked(relayURL, state)
}

func (s *RelaySet) AdvertisedDescriptors() []types.RelayDescriptor {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	projections := s.descriptorProjectionsLocked()
	if len(projections) == 0 {
		return nil
	}

	out := make([]types.RelayDescriptor, 0, len(projections))
	for _, projection := range projections {
		if projection.state.Banned || projection.state.status != relayStatusConfirmed || relayExpiredAt(projection.state, now) {
			continue
		}
		out = append(out, projection.state.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) confirmableDescriptors() []types.RelayDescriptor {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	projections := s.descriptorProjectionsLocked()
	if len(projections) == 0 {
		return nil
	}

	out := make([]types.RelayDescriptor, 0, len(projections))
	for _, projection := range projections {
		if projection.bootstrap || projection.state.Banned || relayExpiredAt(projection.state, now) {
			continue
		}
		out = append(out, projection.state.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) SyncableDescriptors() []types.RelayDescriptor {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	projections := s.descriptorProjectionsLocked()
	if len(projections) == 0 {
		return nil
	}

	out := make([]types.RelayDescriptor, 0, len(projections))
	for _, projection := range projections {
		if projection.bootstrap || projection.state.Banned || relayExpiredAt(projection.state, now) || !projection.state.Descriptor.SupportsOverlayPeer {
			continue
		}
		out = append(out, projection.state.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) View() map[string]RelayState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	projections := s.descriptorProjectionsLocked()
	if len(projections) == 0 {
		return nil
	}

	view := make(map[string]RelayState, len(projections))
	for _, projection := range projections {
		relayKey := projection.state.Descriptor.Key()
		if relayKey == "" {
			continue
		}
		expired := relayExpiredAt(projection.state, now)
		view[relayKey] = RelayState{
			Descriptor:  projection.state.Descriptor,
			FirstSeenAt: projection.state.FirstSeenAt,
			LastSeenAt:  projection.state.LastSeenAt,
			Banned:      projection.state.Banned,
			Expired:     expired,
		}
	}
	if len(view) == 0 {
		return nil
	}
	return view
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
		if _, ok := s.relayKeysByURL[relayURL]; ok {
			continue
		}
		if state := s.localByURL[relayURL]; state.isDefaultLocalState() {
			delete(s.localByURL, relayURL)
		}
	}

	s.knownRelayURLs = append([]string(nil), filtered...)
	return nil
}

func (s *RelaySet) registerDescriptor(desc types.RelayDescriptor, now time.Time) (string, bool, bool, error) {
	normalized, err := NormalizeDescriptor(desc)
	if err != nil {
		return "", false, false, err
	}
	relayKey := normalized.Key()
	if relayKey == "" {
		return "", false, false, errors.New("descriptor identity is required")
	}
	if knownRelayKey, ok := s.relayKeysByURL[normalized.APIHTTPSAddr]; ok && knownRelayKey != relayKey {
		return "", false, false, errors.New("descriptor identity does not match known relay url")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	record, ok := s.relays[relayKey]
	added := !ok
	if !ok {
		record.FirstSeenAt = now
	}
	previousURL := record.Descriptor.APIHTTPSAddr
	previousDescriptor := record.Descriptor
	record.Descriptor = normalized
	record.LastSeenAt = now
	s.relays[relayKey] = record
	s.relayKeysByURL[normalized.APIHTTPSAddr] = relayKey
	if previousURL != "" && previousURL != normalized.APIHTTPSAddr {
		delete(s.relayKeysByURL, previousURL)
		state := s.localByURL[previousURL]
		bootstrap := false
		if !s.isSelfRelayURLLocked(previousURL) {
			if slices.Contains(s.knownRelayURLs, previousURL) {
				bootstrap = true
			}
		}
		if !bootstrap && state.isDefaultLocalState() {
			delete(s.localByURL, previousURL)
		}
	}

	changed := added || !reflect.DeepEqual(previousDescriptor, normalized)
	return relayKey, added, changed, nil
}

func (s *RelaySet) applyDiscoveryDescriptorsLocked(targetIdentity types.Identity, targetURL string, selfDescriptor types.RelayDescriptor, relayDescriptors []types.RelayDescriptor, now time.Time) (relaySetChanged bool, err error) {
	if strings.TrimSpace(targetIdentity.Name) == "" && strings.TrimSpace(targetIdentity.Address) == "" {
		return false, errors.New("target relay identity is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := ValidateDescriptorTarget(selfDescriptor, targetIdentity, targetURL); err != nil {
		return false, err
	}

	apply := func(desc types.RelayDescriptor, advertise bool) error {
		if !advertise && s.isSelfRelayDescriptorLocked(desc) {
			return nil
		}

		_, added, descriptorChanged, err := s.registerDescriptor(desc, now)
		if err != nil {
			return err
		}

		localState := s.localByURL[desc.APIHTTPSAddr]
		previousState := localState
		if advertise {
			localState.status = relayStatusConfirmed
			localState.consecutiveFailures = 0
		} else if localState.status != relayStatusConfirmed {
			localState.status = relayStatusHinted
			localState.consecutiveFailures = 0
		}
		s.storeLocalStateLocked(desc.APIHTTPSAddr, localState)

		changed := added || descriptorChanged || !reflect.DeepEqual(previousState, localState)
		if changed {
			relaySetChanged = true
		}
		return nil
	}

	if err := apply(selfDescriptor, true); err != nil {
		return false, err
	}
	for _, relayDescriptor := range relayDescriptors {
		if err := apply(relayDescriptor, false); err != nil {
			return false, err
		}
	}
	state := s.localByURL[selfDescriptor.APIHTTPSAddr]
	state.status = relayStatusConfirmed
	state.consecutiveFailures = 0
	s.storeLocalStateLocked(selfDescriptor.APIHTTPSAddr, state)
	return relaySetChanged, nil
}

func (s *RelaySet) ApplyRelayDiscoveryResponse(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) (relaySetChanged bool, warnErr error, err error) {
	selfDescriptor, relayDescriptors, validateErr := ValidateRelayDiscoveryResponse(resp, now)
	warnErr = validateErr
	if selfDescriptor.Key() == "" {
		return false, warnErr, validateErr
	}
	s.mu.Lock()
	relaySetChanged, err = s.applyDiscoveryDescriptorsLocked(targetIdentity, targetURL, selfDescriptor, relayDescriptors, now)
	s.mu.Unlock()
	if err != nil {
		return false, warnErr, err
	}
	return relaySetChanged, warnErr, nil
}

func (s *RelaySet) ApplyOverlayRelayDiscoveryResponse(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) (relaySetChanged bool, warnErr error, err error) {
	selfDescriptor, relayDescriptors, validateErr := ValidateRelayDiscoveryResponse(resp, now)
	warnErr = validateErr
	if selfDescriptor.Key() == "" {
		return false, warnErr, validateErr
	}
	if err := RequireOverlayRelayDescriptor(selfDescriptor); err != nil {
		return false, warnErr, err
	}

	filteredRelayDescriptors := make([]types.RelayDescriptor, 0, len(relayDescriptors))
	for _, relayDescriptor := range relayDescriptors {
		if s.isSelfRelayDescriptorLocked(relayDescriptor) {
			continue
		}
		if err := RequireOverlayRelayDescriptor(relayDescriptor); err != nil {
			if warnErr == nil {
				warnErr = err
			}
			continue
		}
		filteredRelayDescriptors = append(filteredRelayDescriptors, relayDescriptor)
	}

	s.mu.Lock()
	relaySetChanged, err = s.applyDiscoveryDescriptorsLocked(targetIdentity, targetURL, selfDescriptor, filteredRelayDescriptors, now)
	s.mu.Unlock()
	if err != nil {
		return false, warnErr, err
	}
	return relaySetChanged, warnErr, nil
}

func (s *RelaySet) RecordDiscoveryFailure(identity types.Identity, relayURL string, err error, recoveryFailures int) (expired bool, expireReason string, consecutiveFailures int) {
	relayKey := identity.Key()
	if relayKey == "" {
		return false, "", 0
	}
	relayURL = strings.TrimSpace(relayURL)

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.relays[relayKey]
	if !ok {
		return false, "", 0
	}
	if relayURL == "" || s.relayKeysByURL[relayURL] != relayKey {
		relayURL = record.Descriptor.APIHTTPSAddr
	}
	if relayURL == "" {
		return false, "", 0
	}

	localState := s.localByURL[relayURL]
	localState.consecutiveFailures++
	s.storeLocalStateLocked(relayURL, localState)
	if localState.status != relayStatusExpired && localState.consecutiveFailures >= recoveryFailures {
		state := s.localByURL[record.Descriptor.APIHTTPSAddr]
		state.status = relayStatusExpired
		s.storeLocalStateLocked(record.Descriptor.APIHTTPSAddr, state)
		return true, "recovery", localState.consecutiveFailures
	}

	var apiErr *types.APIRequestError
	if errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusForbidden ||
			apiErr.StatusCode == http.StatusNotFound ||
			apiErr.StatusCode == http.StatusGone) {
		state := s.localByURL[record.Descriptor.APIHTTPSAddr]
		state.status = relayStatusExpired
		s.storeLocalStateLocked(record.Descriptor.APIHTTPSAddr, state)
		return true, "status", localState.consecutiveFailures
	}
	return false, "", localState.consecutiveFailures
}
