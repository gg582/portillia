package discovery

import (
	"errors"
	"net/http"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type RelayPolicy interface {
	SelectActive([]RelayState) []RelayState
	SelectAdvertised([]RelayState) []RelayState
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

func (p DefaultRelayPolicy) SelectAdvertised(states []RelayState) []RelayState {
	return p.selectStates(states, func(state RelayState) bool {
		return state.Confirmed
	})
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
