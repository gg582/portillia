package discovery

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type RelayView struct {
	Descriptor  types.RelayDescriptor
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

type RelayLocalState struct {
	Banned              bool
	BanReason           string
	Bootstrap           bool
	Advertised          bool
	Expired             bool
	Reachable           bool
	ConsecutiveFailures int
	LastSuccessAt       time.Time
	LastFailureAt       time.Time
}

type RelaySummary struct {
	Known       int
	Banned      int
	Bootstrap   int
	Advertised  int
	Expired     int
	Syncable    int
	Reachable   int
	Unreachable int
}

// RelaySet owns the shared relay discovery view: known relay URLs, stable relay
// id/url mappings, the latest validated descriptor seen for each relay, and common
// process-local relay state such as ban/reachability/failure tracking.
//
// Runtime-specific policy such as bootstrap classification, relay lifecycle, or
// listener ownership belongs in the caller's projection.
type RelaySet struct {
	mu                  sync.RWMutex
	knownRelayURLs      []string
	relayKeysByURL      map[string]string
	relays              map[string]RelayView
	localByURL          map[string]RelayLocalState
	lastStatusReachable map[string]bool
	lastStatusSummary   RelaySummary
	haveLastStatus      bool
	selfRelayKey        string
	selfRelayURL        string
}

const defaultDiscoveryRecoveryFailures = 3

func NewRelaySet() *RelaySet {
	return &RelaySet{
		relayKeysByURL: make(map[string]string),
		relays:         make(map[string]RelayView),
		localByURL:     make(map[string]RelayLocalState),
	}
}

func (s *RelaySet) isSelfRelayURLLocked(relayURL string) bool {
	if s == nil {
		return false
	}
	relayURL = strings.TrimSpace(relayURL)
	return relayURL != "" && s.selfRelayURL != "" && relayURL == s.selfRelayURL
}

func (s *RelaySet) isSelfRelayDescriptorLocked(desc types.RelayDescriptor) bool {
	if s == nil {
		return false
	}
	if s.selfRelayKey != "" {
		if relayKey := desc.Key(); relayKey != "" && relayKey == s.selfRelayKey {
			return true
		}
	}
	return s.isSelfRelayURLLocked(desc.APIHTTPSAddr)
}

func (s *RelaySet) pruneSelfRelayLocked() {
	if s == nil {
		return
	}
	if s.selfRelayURL != "" {
		filtered := s.knownRelayURLs[:0]
		for _, relayURL := range s.knownRelayURLs {
			if s.isSelfRelayURLLocked(relayURL) {
				continue
			}
			filtered = append(filtered, relayURL)
		}
		s.knownRelayURLs = filtered
		delete(s.localByURL, s.selfRelayURL)
		delete(s.relayKeysByURL, s.selfRelayURL)
	}
	if s.selfRelayKey != "" {
		if view, ok := s.relays[s.selfRelayKey]; ok {
			delete(s.localByURL, view.Descriptor.APIHTTPSAddr)
			delete(s.relayKeysByURL, view.Descriptor.APIHTTPSAddr)
		}
		delete(s.relays, s.selfRelayKey)
	}
}

// SetSelfRelay configures the relay set with the local relay identity so it
// can skip self-references when evaluating discovery hints.
func (s *RelaySet) SetSelfRelay(identity types.Identity, relayURL string) error {
	if s == nil {
		return nil
	}
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
	s.pruneSelfRelayLocked()
	s.logStatusChange()
	return nil
}

func (s *RelaySet) trackedRelayURLs() []string {
	if s == nil {
		return nil
	}

	urls := make([]string, 0, len(s.knownRelayURLs)+len(s.relays))
	seen := make(map[string]struct{}, len(s.knownRelayURLs)+len(s.relays))
	for _, relayURL := range s.knownRelayURLs {
		relayURL = strings.TrimSpace(relayURL)
		if relayURL == "" {
			continue
		}
		if _, ok := seen[relayURL]; ok {
			continue
		}
		seen[relayURL] = struct{}{}
		urls = append(urls, relayURL)
	}
	for _, view := range s.relays {
		relayURL := view.Descriptor.APIHTTPSAddr
		if relayURL == "" {
			continue
		}
		if _, ok := seen[relayURL]; ok {
			continue
		}
		seen[relayURL] = struct{}{}
		urls = append(urls, relayURL)
	}
	return urls
}

func (s *RelaySet) ActiveRelayURLs() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.knownRelayURLs) == 0 {
		return nil
	}

	out := make([]string, 0, len(s.knownRelayURLs))
	for _, relayURL := range s.knownRelayURLs {
		if state, ok := s.localByURL[relayURL]; ok && state.Banned {
			continue
		}
		out = append(out, relayURL)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func relayExpiredAt(view RelayView, state RelayLocalState, now time.Time) bool {
	if state.Expired {
		return true
	}
	if view.Descriptor.ExpiresAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !view.Descriptor.ExpiresAt.After(now)
}

func (s *RelaySet) logStatusChange() {
	now := time.Now().UTC()
	var currentReachable map[string]bool
	trackedRelayURLs := s.trackedRelayURLs()
	if len(trackedRelayURLs) > 0 {
		currentReachable = make(map[string]bool, len(trackedRelayURLs))
		for _, relayURL := range trackedRelayURLs {
			state := s.localByURL[relayURL]
			currentReachable[relayURL] = !state.Banned && state.Reachable
		}
	}
	summary := RelaySummary{}
	for _, relayURL := range trackedRelayURLs {
		summary.Known++
		state := s.localByURL[relayURL]
		relayKey := s.relayKeysByURL[relayURL]
		view, ok := s.relays[relayKey]
		expired := ok && relayExpiredAt(view, state, now) || !ok && state.Expired
		if state.Banned {
			summary.Banned++
			continue
		}
		if state.Bootstrap {
			summary.Bootstrap++
		}
		if state.Advertised && !expired {
			summary.Advertised++
		}
		if expired {
			summary.Expired++
		}
		if state.Reachable {
			summary.Reachable++
		} else {
			summary.Unreachable++
		}
		if ok && !state.Bootstrap && !expired && view.Descriptor.SupportsOverlayPeer {
			summary.Syncable++
		}
	}
	if s.haveLastStatus && summary == s.lastStatusSummary && reflect.DeepEqual(currentReachable, s.lastStatusReachable) {
		return
	}

	activated := make([]string, 0)
	deactivated := make([]string, 0)
	for relayURL, reachable := range currentReachable {
		if s.lastStatusReachable == nil || s.lastStatusReachable[relayURL] == reachable {
			continue
		}
		if reachable {
			activated = append(activated, relayURL)
		} else {
			deactivated = append(deactivated, relayURL)
		}
	}
	for relayURL, reachable := range s.lastStatusReachable {
		if _, ok := currentReachable[relayURL]; ok || !reachable {
			continue
		}
		deactivated = append(deactivated, relayURL)
	}

	event := log.Info().
		Int("banned", summary.Banned).
		Int("bootstrap", summary.Bootstrap).
		Int("advertised", summary.Advertised).
		Int("expired", summary.Expired).
		Int("syncable", summary.Syncable).
		Int("reachable", summary.Reachable).
		Int("unreachable", summary.Unreachable)
	if len(activated) > 0 {
		event = event.Strs("activated", activated)
	}
	if len(deactivated) > 0 {
		event = event.Strs("deactivated", deactivated)
	}
	event.Msg("relay status")
	s.lastStatusReachable = currentReachable
	s.lastStatusSummary = summary
	s.haveLastStatus = true
}

func (s *RelaySet) BootstrapDescriptors() []types.RelayDescriptor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.knownRelayURLs) == 0 {
		return nil
	}

	out := make([]types.RelayDescriptor, 0, len(s.knownRelayURLs))
	for _, relayURL := range s.knownRelayURLs {
		state, ok := s.localByURL[relayURL]
		if !ok || !state.Bootstrap {
			continue
		}
		if relayKey, ok := s.relayKeysByURL[relayURL]; ok {
			if view, ok := s.relays[relayKey]; ok && view.Descriptor.APIHTTPSAddr != "" {
				out = append(out, view.Descriptor)
				continue
			}
		}
		out = append(out, types.RelayDescriptor{
			Identity: types.Identity{
				Name: utils.PortalRootHost(relayURL),
			},
			APIHTTPSAddr: relayURL,
			Version:      1,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) ActiveRelayDescriptors() []types.RelayDescriptor {
	advertised := s.AdvertisedDescriptors()
	if len(advertised) == 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	filtered := advertised[:0]
	for _, desc := range advertised {
		if s.isSelfRelayDescriptorLocked(desc) {
			continue
		}
		filtered = append(filtered, desc)
	}
	if len(filtered) == 0 {
		return nil
	}
	return append([]types.RelayDescriptor(nil), filtered...)
}

func (s *RelaySet) BanRelayURL(relayURL, reason string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return false
	}

	state := s.localByURL[relayURL]
	reason = strings.TrimSpace(reason)
	changed := !state.Banned || strings.TrimSpace(state.BanReason) != reason
	state.Banned = true
	state.BanReason = reason
	state.Reachable = false
	s.localByURL[relayURL] = state
	if changed {
		s.logStatusChange()
	}
	return changed
}

func (s *RelaySet) MarkRelayUnreachable(relayURL string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return false
	}

	state := s.localByURL[relayURL]
	if state.Banned {
		return false
	}
	if !state.Reachable {
		return false
	}
	state.Reachable = false
	s.localByURL[relayURL] = state
	s.logStatusChange()
	return true
}

func (s *RelaySet) MarkRelayReachable(relayURL string, now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	state := s.localByURL[relayURL]
	changed := !state.Reachable || state.ConsecutiveFailures != 0 || state.LastSuccessAt != now
	state.Reachable = true
	state.ConsecutiveFailures = 0
	state.LastSuccessAt = now
	s.localByURL[relayURL] = state
	if changed {
		s.logStatusChange()
	}
	return changed
}

func (s *RelaySet) MarkRelayFailure(relayURL string, now time.Time) RelayLocalState {
	if s == nil {
		return RelayLocalState{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return RelayLocalState{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	state := s.localByURL[relayURL]
	state.Reachable = false
	state.ConsecutiveFailures++
	state.LastFailureAt = now
	s.localByURL[relayURL] = state
	s.logStatusChange()
	return state
}

func (s *RelaySet) RecordBootstrapDiscoveryFailure(relayURL string, err error, now time.Time) {
	state := s.MarkRelayFailure(relayURL, now)
	if statusCode, code, unavailable := DiscoveryUnavailableStatus(err); unavailable {
		if state.ConsecutiveFailures > 1 {
			return
		}
		event := log.Info().Str("relay", relayURL)
		if statusCode > 0 {
			event = event.Int("status_code", statusCode)
		}
		if code != "" {
			event = event.Str("code", code)
		}
		event.Msg("bootstrap relay discovery unavailable; peer may have discovery disabled")
		return
	}

	log.Warn().
		Err(err).
		Str("relay", relayURL).
		Msg("bootstrap relay discovery failed")
}

func (s *RelaySet) AdvertisedDescriptors() []types.RelayDescriptor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.relays) == 0 {
		return nil
	}

	now := time.Now().UTC()
	out := make([]types.RelayDescriptor, 0, len(s.relays))
	for _, view := range s.relays {
		state := s.localByURL[view.Descriptor.APIHTTPSAddr]
		if !state.Advertised || relayExpiredAt(view, state, now) || view.Descriptor.APIHTTPSAddr == "" {
			continue
		}
		out = append(out, view.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].APIHTTPSAddr < out[j].APIHTTPSAddr
	})
	return out
}

func (s *RelaySet) SyncableDescriptors() []types.RelayDescriptor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.relays) == 0 {
		return nil
	}

	now := time.Now().UTC()
	out := make([]types.RelayDescriptor, 0, len(s.relays))
	for _, view := range s.relays {
		state := s.localByURL[view.Descriptor.APIHTTPSAddr]
		if state.Bootstrap || relayExpiredAt(view, state, now) || !view.Descriptor.SupportsOverlayPeer {
			continue
		}
		out = append(out, view.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].APIHTTPSAddr < out[j].APIHTTPSAddr
	})
	return out
}

func (s *RelaySet) Snapshot() map[string]types.RelayState {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.relays) == 0 {
		return nil
	}

	now := time.Now().UTC()
	snapshot := make(map[string]types.RelayState, len(s.relays))
	for relayKey, view := range s.relays {
		localState := s.localByURL[view.Descriptor.APIHTTPSAddr]
		snapshot[relayKey] = types.RelayState{
			Descriptor:          view.Descriptor,
			Bootstrap:           localState.Bootstrap,
			Advertised:          localState.Advertised,
			Expired:             relayExpiredAt(view, localState, now),
			FirstSeenAt:         view.FirstSeenAt,
			LastSeenAt:          view.LastSeenAt,
			ConsecutiveFailures: localState.ConsecutiveFailures,
		}
	}
	return snapshot
}

func (s *RelaySet) ReplaceKnownRelayURLs(relayURLs []string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := make([]string, 0, len(relayURLs))
	for _, relayURL := range relayURLs {
		relayURL = strings.TrimSpace(relayURL)
		if relayURL == "" {
			continue
		}
		duplicate := false
		for _, existing := range filtered {
			if existing == relayURL {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		filtered = append(filtered, relayURL)
	}
	s.knownRelayURLs = append([]string(nil), filtered...)
}

func (s *RelaySet) SetBootstrapRelayURLs(relayURLs []string) {
	if s == nil {
		return
	}
	normalized := make([]string, 0, len(relayURLs))
	seen := make(map[string]struct{}, len(relayURLs))
	for _, relayURL := range relayURLs {
		relayURL = strings.TrimSpace(relayURL)
		if relayURL == "" {
			continue
		}
		parsed, err := utils.NormalizeRelayURL(relayURL)
		if err != nil {
			log.Warn().
				Err(err).
				Str("relay_url", relayURL).
				Msg("skip invalid bootstrap relay url")
			continue
		}
		if _, ok := seen[parsed]; ok {
			continue
		}
		seen[parsed] = struct{}{}
		normalized = append(normalized, parsed)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := normalized[:0]
	for _, relayURL := range normalized {
		if s.isSelfRelayURLLocked(relayURL) {
			continue
		}
		filtered = append(filtered, relayURL)
		state := s.localByURL[relayURL]
		state.Bootstrap = true
		s.localByURL[relayURL] = state
	}
	normalized = filtered

	current := make(map[string]struct{}, len(normalized))
	for _, relayURL := range normalized {
		current[relayURL] = struct{}{}
	}

	existing := make(map[string]struct{}, len(s.knownRelayURLs))
	for _, relayURL := range s.knownRelayURLs {
		existing[relayURL] = struct{}{}
		if _, ok := current[relayURL]; !ok {
			state := s.localByURL[relayURL]
			if state.Bootstrap {
				state.Bootstrap = false
				s.localByURL[relayURL] = state
			}
		}
	}
	s.knownRelayURLs = append([]string(nil), normalized...)
	s.logStatusChange()
}

func (s *RelaySet) mergeKnownRelayURLs(relayURLs []string) error {
	if s == nil || len(relayURLs) == 0 {
		return nil
	}
	normalized, err := utils.NormalizeRelayURLs(relayURLs...)
	if err != nil {
		return err
	}
	if len(normalized) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing := make(map[string]struct{}, len(s.knownRelayURLs))
	for _, relayURL := range s.knownRelayURLs {
		existing[relayURL] = struct{}{}
	}

	changed := false
	for _, relayURL := range normalized {
		if s.isSelfRelayURLLocked(relayURL) {
			continue
		}
		if _, ok := existing[relayURL]; ok {
			continue
		}
		existing[relayURL] = struct{}{}
		s.knownRelayURLs = append(s.knownRelayURLs, relayURL)
		state := s.localByURL[relayURL]
		s.localByURL[relayURL] = state
		changed = true
	}
	if changed {
		s.logStatusChange()
	}
	return nil
}

func (s *RelaySet) registerDescriptor(desc types.RelayDescriptor, now time.Time) (string, bool, bool, error) {
	if s == nil {
		return "", false, false, nil
	}
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

	view, ok := s.relays[relayKey]
	added := !ok
	if !ok {
		view.FirstSeenAt = now
	}
	previousURL := view.Descriptor.APIHTTPSAddr
	previousDescriptor := view.Descriptor
	view.Descriptor = normalized
	view.LastSeenAt = now
	s.relays[relayKey] = view
	s.relayKeysByURL[normalized.APIHTTPSAddr] = relayKey
	if previousURL != "" && previousURL != normalized.APIHTTPSAddr {
		delete(s.relayKeysByURL, previousURL)
	}

	changed := added || !reflect.DeepEqual(previousDescriptor, normalized)
	return relayKey, added, changed, nil
}

func relayDiscoveryURLs(selfDescriptor types.RelayDescriptor, relayDescriptors []types.RelayDescriptor) []string {
	relayURLs := make([]string, 0, 1+len(relayDescriptors))
	if apiURL := selfDescriptor.APIHTTPSAddr; apiURL != "" {
		relayURLs = append(relayURLs, apiURL)
	}
	for _, relayDescriptor := range relayDescriptors {
		if apiURL := relayDescriptor.APIHTTPSAddr; apiURL != "" {
			relayURLs = append(relayURLs, apiURL)
		}
	}
	if len(relayURLs) == 0 {
		return nil
	}
	return relayURLs
}

func (s *RelaySet) applyDiscoveryDescriptors(targetIdentity types.Identity, targetURL string, selfDescriptor types.RelayDescriptor, relayDescriptors []types.RelayDescriptor, now time.Time) (relaySetChanged bool, addedRelayCount int, err error) {
	if s == nil {
		return false, 0, nil
	}
	if strings.TrimSpace(targetIdentity.Name) == "" && strings.TrimSpace(targetIdentity.Address) == "" {
		return false, 0, errors.New("target relay identity is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := ValidateDescriptorTarget(selfDescriptor, targetIdentity, targetURL); err != nil {
		return false, 0, err
	}

	apply := func(desc types.RelayDescriptor, advertise, countAdded bool) error {
		_, added, descriptorChanged, err := s.registerDescriptor(desc, now)
		if err != nil {
			return err
		}
		localState := s.localByURL[desc.APIHTTPSAddr]
		wasAdvertised := localState.Advertised
		wasExpired := localState.Expired
		if advertise {
			localState.Advertised = true
		}
		localState.Expired = false
		s.localByURL[desc.APIHTTPSAddr] = localState

		changed := added || descriptorChanged || advertise && !wasAdvertised || wasExpired
		if added && countAdded {
			addedRelayCount++
		}
		if changed {
			relaySetChanged = true
		}
		return nil
	}

	if err := apply(selfDescriptor, true, false); err != nil {
		return false, 0, err
	}
	for _, relayDescriptor := range relayDescriptors {
		if s.isSelfRelayDescriptorLocked(relayDescriptor) {
			continue
		}
		if err := apply(relayDescriptor, false, true); err != nil {
			return false, 0, err
		}
	}
	state := s.localByURL[selfDescriptor.APIHTTPSAddr]
	state.Reachable = true
	state.ConsecutiveFailures = 0
	state.LastSuccessAt = now
	s.localByURL[selfDescriptor.APIHTTPSAddr] = state
	s.logStatusChange()
	return relaySetChanged, addedRelayCount, nil
}

func (s *RelaySet) ApplyRelayDiscoveryResponse(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) (relayURLs []string, relaySetChanged bool, addedRelayCount int, warnErr error, err error) {
	selfDescriptor, relayDescriptors, validateErr := ValidateRelayDiscoveryResponse(resp, now)
	warnErr = validateErr
	if selfDescriptor.Key() == "" {
		return nil, false, 0, warnErr, validateErr
	}
	s.mu.Lock()
	relaySetChanged, addedRelayCount, err = s.applyDiscoveryDescriptors(targetIdentity, targetURL, selfDescriptor, relayDescriptors, now)
	s.mu.Unlock()
	if err != nil {
		return nil, false, 0, warnErr, err
	}
	return relayDiscoveryURLs(selfDescriptor, relayDescriptors), relaySetChanged, addedRelayCount, warnErr, nil
}

func (s *RelaySet) ApplyOverlayRelayDiscoveryResponse(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) (relayURLs []string, relaySetChanged bool, addedRelayCount int, warnErr error, err error) {
	selfDescriptor, relayDescriptors, validateErr := ValidateRelayDiscoveryResponse(resp, now)
	warnErr = validateErr
	if selfDescriptor.Key() == "" {
		return nil, false, 0, warnErr, validateErr
	}
	if err := RequireOverlayRelayDescriptor(selfDescriptor); err != nil {
		return nil, false, 0, warnErr, err
	}

	filteredRelayDescriptors := make([]types.RelayDescriptor, 0, len(relayDescriptors))
	for _, relayDescriptor := range relayDescriptors {
		if err := RequireOverlayRelayDescriptor(relayDescriptor); err != nil {
			if warnErr == nil {
				warnErr = err
			}
			continue
		}
		filteredRelayDescriptors = append(filteredRelayDescriptors, relayDescriptor)
	}

	s.mu.Lock()
	relaySetChanged, addedRelayCount, err = s.applyDiscoveryDescriptors(targetIdentity, targetURL, selfDescriptor, filteredRelayDescriptors, now)
	s.mu.Unlock()
	if err != nil {
		return nil, false, 0, warnErr, err
	}
	return relayDiscoveryURLs(selfDescriptor, filteredRelayDescriptors), relaySetChanged, addedRelayCount, warnErr, nil
}

func (s *RelaySet) ApplyRelayDiscoveryResponseSimple(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) error {
	relayURLs, _, _, warnErr, err := s.ApplyRelayDiscoveryResponse(targetIdentity, targetURL, resp, now)
	if warnErr != nil {
		log.Warn().
			Err(warnErr).
			Str("relay", targetURL).
			Msg("relay discovery response completed with warnings")
	}
	if err != nil {
		return err
	}

	targetRelayURL := strings.TrimSpace(resp.Self.APIHTTPSAddr)
	if targetRelayURL == "" && len(relayURLs) > 0 {
		targetRelayURL = relayURLs[0]
	}
	if targetRelayURL == "" {
		return nil
	}
	if err := s.mergeKnownRelayURLs([]string{targetRelayURL}); err != nil {
		return err
	}
	return nil
}

func (s *RelaySet) RegisterBootstrapRelayURLs(inputs []string) ([]string, error) {
	if s == nil || len(inputs) == 0 {
		return nil, nil
	}

	normalized, err := utils.NormalizeRelayURLs(inputs...)
	if err != nil {
		return nil, err
	}
	normalized, err = utils.ExcludeLocalRelayURLs(normalized...)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := make(map[string]struct{}, len(s.knownRelayURLs))
	for _, relayURL := range s.knownRelayURLs {
		existing[relayURL] = struct{}{}
	}
	added := make([]string, 0, len(normalized))
	for _, relayURL := range normalized {
		if _, ok := existing[relayURL]; ok {
			continue
		}
		existing[relayURL] = struct{}{}
		s.knownRelayURLs = append(s.knownRelayURLs, relayURL)
		added = append(added, relayURL)
	}
	for _, relayURL := range normalized {
		state := s.localByURL[relayURL]
		state.Bootstrap = true
		state.Reachable = false
		s.localByURL[relayURL] = state
	}
	s.logStatusChange()
	if len(added) == 0 {
		return nil, nil
	}
	return added, nil
}

func (s *RelaySet) refreshBootstrapDiscovery(ctx context.Context, rootCAPEM []byte) error {
	bootstraps := s.BootstrapDescriptors()
	for _, bootstrap := range bootstraps {
		resp, err := DiscoverRelayDiscovery(ctx, bootstrap.APIHTTPSAddr, rootCAPEM, nil)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.RecordBootstrapDiscoveryFailure(bootstrap.APIHTTPSAddr, err, time.Now().UTC())
			continue
		}

		now := time.Now().UTC()
		relayURLs, _, _, warnErr, applyErr := s.ApplyRelayDiscoveryResponse(bootstrap.Identity, bootstrap.APIHTTPSAddr, resp, now)
		if warnErr != nil {
			log.Warn().
				Err(warnErr).
				Str("relay", bootstrap.APIHTTPSAddr).
				Msg("bootstrap relay discovery completed with warnings")
		}
		if applyErr != nil {
			s.MarkRelayFailure(bootstrap.APIHTTPSAddr, now)
			log.Warn().
				Err(applyErr).
				Str("relay", bootstrap.APIHTTPSAddr).
				Msg("bootstrap relay discovery failed")
			continue
		}
		if len(relayURLs) == 0 {
			continue
		}
		if err := s.mergeKnownRelayURLs(relayURLs); err != nil {
			log.Warn().
				Err(err).
				Str("relay", bootstrap.APIHTTPSAddr).
				Msg("merge discovered relay urls")
		}
	}
	return nil
}

func (s *RelaySet) RunLoop(ctx context.Context, rootCAPEM []byte, syncRuntime func() error) error {
	if s == nil {
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(types.DiscoveryPollInterval)
	defer ticker.Stop()

	for {
		if err := s.refreshBootstrapDiscovery(ctx, rootCAPEM); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if syncRuntime != nil {
			if err := syncRuntime(); err != nil {
				return err
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *RelaySet) RecordDiscoveryFailure(identity types.Identity, relayURL string, err error) (expired bool, expireReason string, consecutiveFailures int) {
	return s.RecordDiscoveryFailureWithRecovery(identity, relayURL, err, defaultDiscoveryRecoveryFailures, time.Now().UTC())
}

func (s *RelaySet) RecordDiscoveryFailureWithRecovery(identity types.Identity, relayURL string, err error, recoveryFailures int, now time.Time) (expired bool, expireReason string, consecutiveFailures int) {
	if s == nil {
		return false, "", 0
	}
	relayKey := identity.Key()
	if relayKey == "" {
		return false, "", 0
	}
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return false, "", 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	view, ok := s.relays[relayKey]
	if !ok {
		return false, "", 0
	}

	localState := s.localByURL[relayURL]
	localState.Reachable = false
	localState.ConsecutiveFailures++
	localState.LastFailureAt = now
	s.localByURL[relayURL] = localState
	s.logStatusChange()
	if !localState.Expired && localState.ConsecutiveFailures >= recoveryFailures {
		state := s.localByURL[view.Descriptor.APIHTTPSAddr]
		state.Advertised = false
		state.Expired = true
		s.localByURL[view.Descriptor.APIHTTPSAddr] = state
		s.logStatusChange()
		return true, "recovery", localState.ConsecutiveFailures
	}

	var apiErr *types.APIRequestError
	if errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusForbidden ||
			apiErr.StatusCode == http.StatusNotFound ||
			apiErr.StatusCode == http.StatusGone) {
		state := s.localByURL[view.Descriptor.APIHTTPSAddr]
		state.Advertised = false
		state.Expired = true
		s.localByURL[view.Descriptor.APIHTTPSAddr] = state
		s.logStatusChange()
		return true, "status", localState.ConsecutiveFailures
	}
	return false, "", localState.ConsecutiveFailures
}
