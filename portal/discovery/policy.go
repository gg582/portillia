package discovery

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type RelayStatus uint8

const (
	RelayStatusUnknown RelayStatus = iota
	RelayStatusHinted
	RelayStatusConfirmed
	RelayStatusInvalid
	RelayStatusExpired
	RelayStatusBanned
)

type RelayState struct {
	Descriptor         types.RelayDescriptor
	Bootstrap          bool
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
	Status             RelayStatus
	Active             bool
	Advertise          bool
	BootstrapDiscovery bool
	DirectDiscovery    bool
	OverlayDiscovery   bool
	OverlayPeer        bool

	consecutiveFailures int
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

	switch {
	case normalized.Name == "":
		return RelayState{}, errors.New("identity.name is required")
	case normalized.APIHTTPSAddr == "":
		return RelayState{}, errors.New("api_https_addr is required")
	case normalized.RelayID == "":
		return RelayState{}, errors.New("relay_id is required")
	case normalized.RelayID != normalized.APIHTTPSAddr:
		return RelayState{}, errors.New("relay_id must match api_https_addr")
	case normalized.Sequence == 0:
		return RelayState{}, errors.New("sequence is required")
	case normalized.Version == 0:
		return RelayState{}, errors.New("version is required")
	case normalized.IssuedAt.IsZero():
		return RelayState{}, errors.New("issued_at is required")
	case normalized.ExpiresAt.IsZero():
		return RelayState{}, errors.New("expires_at is required")
	case normalized.ExpiresAt.Before(seenAt):
		return RelayState{}, errors.New("descriptor expired")
	case normalized.IssuedAt.After(normalized.ExpiresAt):
		return RelayState{}, errors.New("issued_at must be before expires_at")
	}

	state.Descriptor = normalized
	state.FirstSeenAt = seenAt
	state.LastSeenAt = seenAt
	return state, nil
}

func newRelayHintState(relayURL string) RelayState {
	state, _ := newRelayState(
		types.RelayDescriptor{
			Identity: types.Identity{
				Name: utils.PortalRootHost(relayURL),
			},
			RelayID:      relayURL,
			APIHTTPSAddr: relayURL,
			Version:      1,
		},
		time.Time{},
	)
	return state
}

func (DefaultRelayPolicy) DiscoveryStates(targetIdentity types.Identity, targetURL string, selfRelayKey string, selfRelayURL string, resp types.DiscoveryResponse, seenAt time.Time) (RelayState, []RelayState, error) {
	protocolVersion := strings.TrimSpace(resp.ProtocolVersion)
	if protocolVersion != types.ProtocolVersion {
		return RelayState{}, nil, fmt.Errorf("relay protocol version mismatch: relay=%q client=%q", protocolVersion, types.ProtocolVersion)
	}

	selfState, err := newRelayState(resp.Self, seenAt)
	if err != nil {
		return RelayState{}, nil, err
	}
	if err := requireTargetRelayDescriptor(selfState.Descriptor, targetIdentity, targetURL); err != nil {
		return RelayState{}, nil, err
	}

	relayStates := make([]RelayState, 0, len(resp.Relays))
	seen := map[string]struct{}{selfState.Descriptor.Key(): {}}
	for _, descriptor := range resp.Relays {
		relayState, err := newRelayState(descriptor, seenAt)
		if err != nil {
			continue
		}
		if selfRelay(relayState, selfRelayKey, selfRelayURL) {
			continue
		}
		relayKey := relayState.Descriptor.Key()
		if _, ok := seen[relayKey]; ok {
			continue
		}
		seen[relayKey] = struct{}{}
		relayStates = append(relayStates, relayState)
	}
	return selfState, relayStates, nil
}

func selfRelay(state RelayState, selfRelayKey string, selfRelayURL string) bool {
	desc := state.Descriptor
	relayKey := desc.Key()
	return (relayKey != "" && selfRelayKey != "" && relayKey == selfRelayKey) ||
		(selfRelayURL != "" && desc.APIHTTPSAddr == selfRelayURL)
}

func requireTargetRelayDescriptor(desc types.RelayDescriptor, targetIdentity types.Identity, targetURL string) error {
	if strings.TrimSpace(targetIdentity.Name) == "" && strings.TrimSpace(targetIdentity.Address) == "" {
		return errors.New("target relay identity is required")
	}
	targetName := strings.TrimSpace(targetIdentity.Name)
	if targetName != "" {
		normalizedTargetName := utils.NormalizeHostname(targetName)
		if desc.Name != normalizedTargetName {
			return errors.New("descriptor name does not match target relay")
		}
	}
	targetAddress := strings.TrimSpace(targetIdentity.Address)
	if targetAddress != "" {
		normalizedTargetAddress, err := utils.NormalizeEVMAddress(targetAddress)
		if err != nil {
			return err
		}
		if desc.Address != normalizedTargetAddress {
			return errors.New("descriptor address does not match target relay")
		}
	}
	if targetURL != "" {
		normalizedTargetURL, err := utils.NormalizeRelayURL(targetURL)
		if err != nil {
			return err
		}
		if desc.APIHTTPSAddr != normalizedTargetURL {
			return errors.New("descriptor api_https_addr does not match target url")
		}
	}
	return nil
}

func (state RelayState) hasDescriptor() bool {
	return !state.LastSeenAt.IsZero() && state.Descriptor.Key() != "" && state.Descriptor.APIHTTPSAddr != ""
}

type RelayPolicy interface {
	DiscoveryStates(types.Identity, string, string, string, types.DiscoveryResponse, time.Time) (RelayState, []RelayState, error)
	Decide(RelayState) RelayState
	OnDiscovered(RelayState, bool) RelayState
	OnFailure(RelayState, error, int) (RelayState, bool, string)
	OnBanned(RelayState) RelayState
	KeepState(RelayState) bool
	AdvertisedDescriptors([]RelayState) []types.RelayDescriptor
}

type DefaultRelayPolicy struct{}

func (DefaultRelayPolicy) Decide(state RelayState) RelayState {
	now := time.Now().UTC()
	status := state.Status
	switch {
	case status == RelayStatusBanned || status == RelayStatusExpired:
	case !state.Descriptor.ExpiresAt.IsZero() && !state.Descriptor.ExpiresAt.After(now):
		status = RelayStatusExpired
	case state.Descriptor.SupportsOverlayPeer &&
		(state.Descriptor.WireGuardPublicKey == "" ||
			state.Descriptor.WireGuardEndpoint == "" ||
			state.Descriptor.OverlayIPv4 == ""):
		status = RelayStatusInvalid
	case status == RelayStatusUnknown:
		status = RelayStatusHinted
	}

	usable := status == RelayStatusHinted || status == RelayStatusConfirmed
	state.Status = status
	state.Active = (state.Bootstrap && usable) || status == RelayStatusConfirmed
	state.Advertise = status == RelayStatusConfirmed
	state.BootstrapDiscovery = state.Bootstrap && usable
	state.DirectDiscovery = !state.Bootstrap && usable
	state.OverlayDiscovery = !state.Bootstrap && usable && state.Descriptor.SupportsOverlayPeer
	state.OverlayPeer = usable && state.Descriptor.SupportsOverlayPeer
	return state
}

func (DefaultRelayPolicy) OnDiscovered(state RelayState, advertise bool) RelayState {
	if state.Status == RelayStatusBanned {
		return state
	}
	if advertise {
		state.Status = RelayStatusConfirmed
		state.consecutiveFailures = 0
		return state
	}
	if state.Status != RelayStatusConfirmed {
		state.Status = RelayStatusHinted
		state.consecutiveFailures = 0
	}
	return state
}

func (DefaultRelayPolicy) OnFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	if state.Status == RelayStatusBanned {
		return state, false, ""
	}
	state.consecutiveFailures++
	if state.Status != RelayStatusExpired && state.consecutiveFailures >= recoveryFailures {
		state.Status = RelayStatusExpired
		return state, true, "recovery"
	}
	var apiErr *types.APIRequestError
	if errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusForbidden ||
			apiErr.StatusCode == http.StatusNotFound ||
			apiErr.StatusCode == http.StatusGone) {
		state.Status = RelayStatusExpired
		return state, true, "status"
	}
	return state, false, ""
}

func (DefaultRelayPolicy) OnBanned(state RelayState) RelayState {
	state.Status = RelayStatusBanned
	return state
}

func (DefaultRelayPolicy) KeepState(state RelayState) bool {
	return state.hasDescriptor() ||
		state.Status == RelayStatusBanned ||
		state.Status == RelayStatusExpired ||
		state.consecutiveFailures > 0
}

func (p DefaultRelayPolicy) AdvertisedDescriptors(states []RelayState) []types.RelayDescriptor {
	if len(states) == 0 {
		return nil
	}

	out := make([]types.RelayDescriptor, 0, len(states))
	for _, state := range states {
		state = p.Decide(state)
		if state.Descriptor.APIHTTPSAddr == "" || !state.Advertise {
			continue
		}
		out = append(out, state.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].APIHTTPSAddr < out[j].APIHTTPSAddr
	})
	return out
}
