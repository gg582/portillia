package discovery

import (
	"errors"
	"math/rand"
	"net/http"
	"slices"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type RelayPolicy interface {
	SelectActive([]RelayState) []RelayState
	SelectPriority([]RelayState, ClientState) []string
	OnConfirmed(RelayState) RelayState
	OnHinted(RelayState) RelayState
	OnFailure(RelayState, error, int) (RelayState, bool, string)
	OnBanned(RelayState) RelayState
}

type DefaultRelayPolicy struct{}

const highDiscoveryRTTThreshold = 1 * time.Second

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

func (p DefaultRelayPolicy) SelectPriority(states []RelayState, clientState ClientState) []string {
	selected := p.SelectActive(states)
	if len(selected) == 0 {
		return nil
	}

	explicit := make([]string, 0, len(clientState.ExplicitRelayURLs))
	autoPool := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		if clientState.RequireUDP && state.hasDescriptor() && !state.Descriptor.SupportsUDP {
			continue
		}
		if clientState.RequireTCP && state.hasDescriptor() && !state.Descriptor.SupportsTCP {
			continue
		}
		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(clientState.ExplicitRelayURLs, relayURL) {
			explicit = append(explicit, relayURL)
			continue
		}
		autoPool = append(autoPool, state)
	}
	if len(explicit) == 0 && len(autoPool) == 0 {
		return nil
	}

	currentAuto := make([]string, 0, len(autoPool))
	remainingAuto := make([]string, 0, len(autoPool))
	highRTTAuto := make([]string, 0, len(autoPool))
	penalizedAuto := make([]string, 0, len(autoPool))
	for _, state := range autoPool {
		relayURL := state.Descriptor.APIHTTPSAddr
		statePenalized := state.consecutiveFailures > 0 && !state.Reachable
		switch {
		case slices.Contains(clientState.ActiveRelayURLs, relayURL) && !statePenalized:
			currentAuto = append(currentAuto, relayURL)
		case statePenalized:
			penalizedAuto = append(penalizedAuto, relayURL)
		case !state.DiscoveryRTTAt.IsZero() && state.DiscoveryRTT > highDiscoveryRTTThreshold:
			highRTTAuto = append(highRTTAuto, relayURL)
		default:
			remainingAuto = append(remainingAuto, relayURL)
		}
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	if len(remainingAuto) > 1 {
		rng.Shuffle(len(remainingAuto), func(i, j int) {
			remainingAuto[i], remainingAuto[j] = remainingAuto[j], remainingAuto[i]
		})
	}
	if len(penalizedAuto) > 1 {
		rng.Shuffle(len(penalizedAuto), func(i, j int) {
			penalizedAuto[i], penalizedAuto[j] = penalizedAuto[j], penalizedAuto[i]
		})
	}
	if len(highRTTAuto) > 1 {
		rng.Shuffle(len(highRTTAuto), func(i, j int) {
			highRTTAuto[i], highRTTAuto[j] = highRTTAuto[j], highRTTAuto[i]
		})
	}

	autoURLs := make([]string, 0, len(currentAuto)+len(remainingAuto)+len(highRTTAuto)+len(penalizedAuto))
	autoURLs = append(autoURLs, currentAuto...)
	autoURLs = append(autoURLs, remainingAuto...)
	autoURLs = append(autoURLs, highRTTAuto...)
	autoURLs = append(autoURLs, penalizedAuto...)
	if clientState.MaxActiveRelays > 0 && len(autoURLs) > clientState.MaxActiveRelays {
		autoURLs = autoURLs[:clientState.MaxActiveRelays]
	}

	out := make([]string, 0, len(explicit)+len(autoURLs))
	out = append(out, explicit...)
	out = append(out, autoURLs...)
	if len(out) == 0 {
		return nil
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
