package discovery

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type RelayPolicy interface {
	SelectActive([]RelayState) []RelayState
	SelectConfirmed([]RelayState) []RelayState
	SelectPriority([]RelayState, ClientState) []RelayState
	OnConfirmed(RelayState) RelayState
	OnHinted(RelayState) RelayState
	OnFailure(RelayState, error, int) (RelayState, bool, string)
	OnBanned(RelayState) RelayState
}

type DefaultRelayPolicy struct{}

func (p DefaultRelayPolicy) selectStates(states []RelayState, keep func(RelayState) bool) []RelayState {
	now := time.Now().UTC()
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		if !state.discoverable(now) {
			continue
		}
		if !keep(state) {
			continue
		}
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p DefaultRelayPolicy) SelectActive(states []RelayState) []RelayState {
	return p.selectStates(states, func(state RelayState) bool {
		return state.Bootstrap || state.Confirmed
	})
}

func (p DefaultRelayPolicy) SelectConfirmed(states []RelayState) []RelayState {
	return p.selectStates(states, func(state RelayState) bool {
		return state.Confirmed
	})
}

func (p DefaultRelayPolicy) SelectPriority(states []RelayState, clientState ClientState) []RelayState {
	selected := p.SelectActive(states)
	if len(selected) == 0 {
		return nil
	}

	currentRelayURLs := make([]string, 0, len(clientState.ActiveRelayURLs))
	activeRelayURLSet := make(map[string]struct{}, len(clientState.ActiveRelayURLs))
	for _, relayURL := range clientState.ActiveRelayURLs {
		relayURL = strings.TrimSpace(relayURL)
		if relayURL == "" {
			continue
		}
		currentRelayURLs = append(currentRelayURLs, relayURL)
		activeRelayURLSet[relayURL] = struct{}{}
	}

	out := selected[:0]
	for _, state := range selected {
		if clientState.RequireUDP && state.hasDescriptor() && !state.Descriptor.SupportsUDP {
			continue
		}
		if clientState.RequireTCP && state.hasDescriptor() && !state.Descriptor.SupportsTCP {
			continue
		}
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}

	currentRelays := make([]RelayState, 0, len(currentRelayURLs))
	eligibleByURL := make(map[string]RelayState, len(out))
	for _, state := range out {
		eligibleByURL[strings.TrimSpace(state.Descriptor.APIHTTPSAddr)] = state
	}

	currentHealthy := len(currentRelayURLs) > 0
	for _, relayURL := range currentRelayURLs {
		state, ok := eligibleByURL[relayURL]
		if !ok {
			currentHealthy = false
			break
		}
		currentRelays = append(currentRelays, state)
	}
	if currentHealthy && (clientState.MaxActiveRelays <= 0 || len(currentRelays) >= clientState.MaxActiveRelays) {
		return currentRelays
	}

	sort.SliceStable(out, func(i, j int) bool {
		left := out[i]
		right := out[j]

		// 1. Prefer confirmed relays over candidates that are only known through bootstrap discovery.
		if left.Confirmed != right.Confirmed {
			return left.Confirmed
		}

		// 2. Prefer relays the client is already using so a healthy pool stays stable instead of churning.
		_, leftActive := activeRelayURLSet[strings.TrimSpace(left.Descriptor.APIHTTPSAddr)]
		_, rightActive := activeRelayURLSet[strings.TrimSpace(right.Descriptor.APIHTTPSAddr)]
		if leftActive != rightActive {
			return leftActive
		}

		// 3. Prefer bootstrap relays when the stronger signals above are equal.
		if left.Bootstrap != right.Bootstrap {
			return left.Bootstrap
		}

		// 4. Prefer relays reporting lower concurrent load.
		if left.Descriptor.Load != right.Descriptor.Load {
			return left.Descriptor.Load < right.Descriptor.Load
		}

		// 5. Prefer relays reporting lower traffic score after the more stable load signal ties.
		if left.Descriptor.LoadScore != right.Descriptor.LoadScore {
			return left.Descriptor.LoadScore < right.Descriptor.LoadScore
		}

		// 6. Prefer relays with measured discovery RTT, then prefer the lower RTT when both have measurements.
		leftHasRTT := !left.DiscoveryRTTAt.IsZero()
		rightHasRTT := !right.DiscoveryRTTAt.IsZero()
		if leftHasRTT != rightHasRTT {
			return leftHasRTT
		}
		if left.DiscoveryRTT != right.DiscoveryRTT {
			return left.DiscoveryRTT < right.DiscoveryRTT
		}

		// 7. Fall back to URL ordering so selection remains deterministic when all policy signals tie.
		return left.Descriptor.APIHTTPSAddr < right.Descriptor.APIHTTPSAddr
	})

	if clientState.MaxActiveRelays > 0 && len(out) > clientState.MaxActiveRelays {
		out = out[:clientState.MaxActiveRelays]
	}
	return out
}

func (DefaultRelayPolicy) OnConfirmed(state RelayState) RelayState {
	if state.Banned {
		return state
	}
	state.Reachable = true
	state.Confirmed = true
	state.consecutiveFailures = 0
	return state
}

func (DefaultRelayPolicy) OnHinted(state RelayState) RelayState {
	if state.Banned {
		return state
	}
	state.Reachable = true
	if !state.Confirmed {
		state.consecutiveFailures = 0
	}
	return state
}

func (DefaultRelayPolicy) OnFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	if state.Banned {
		return state, false, ""
	}
	state.consecutiveFailures++
	expire := func(reason string) (RelayState, bool, string) {
		if !state.Reachable {
			return state, false, ""
		}
		state.Reachable = false
		state.Confirmed = false
		return state, true, reason
	}
	var apiErr *types.APIRequestError
	if errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusForbidden ||
			apiErr.StatusCode == http.StatusNotFound ||
			apiErr.StatusCode == http.StatusGone) {
		return expire("status")
	}
	if state.consecutiveFailures >= recoveryFailures {
		return expire("recovery")
	}
	return state, false, ""
}

func (DefaultRelayPolicy) OnBanned(state RelayState) RelayState {
	state.Banned = true
	return state
}
