package discovery

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func mustPolicyRelayDescriptor(t *testing.T, relayName, relayURL string) types.RelayDescriptor {
	t.Helper()

	now := time.Now().UTC()
	desc, err := utils.NormalizeDescriptor(types.RelayDescriptor{
		Identity: types.Identity{
			Name: relayName,
		},
		RelayID:      relayURL,
		Version:      1,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: relayURL,
	})
	if err != nil {
		t.Fatalf("NormalizeDescriptor() error = %v", err)
	}
	return desc
}

func bootstrapPolicyRelayState(relayURL string) RelayState {
	return RelayState{
		Descriptor: types.RelayDescriptor{
			Identity: types.Identity{
				Name: utils.PortalRootHost(relayURL),
			},
			RelayID:      relayURL,
			APIHTTPSAddr: relayURL,
		},
		Bootstrap: true,
	}
}

func confirmedPolicyRelayState(t *testing.T, relayName, relayURL string) RelayState {
	t.Helper()

	return RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, relayName, relayURL),
		Reachable:  true,
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

func confirmedPolicyRelayStateWithRTT(t *testing.T, relayName, relayURL string, rtt time.Duration) RelayState {
	t.Helper()

	state := confirmedPolicyRelayState(t, relayName, relayURL)
	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = time.Now().UTC()
	return state
}

func TestSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
	policy := DefaultRelayPolicy{}
	explicitRelay := "https://relay-explicit.example"
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := policy.SelectPriority([]RelayState{
		bootstrapPolicyRelayState(explicitRelay),
		confirmedPolicyRelayState(t, "relay-a", relayA),
		confirmedPolicyRelayState(t, "relay-b", relayB),
	}, ClientState{
		ExplicitRelayURLs: []string{explicitRelay},
		MaxActiveRelays:   1,
	})

	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2", len(selected))
	}
	if got := selected[0]; got != explicitRelay {
		t.Fatalf("selected[0] = %q, want explicit relay %q", got, explicitRelay)
	}
}

func TestSelectPriorityColdStartSelectsEligibleRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := policy.SelectPriority([]RelayState{
		confirmedPolicyRelayState(t, "relay-a", relayA),
		confirmedPolicyRelayState(t, "relay-b", relayB),
	}, ClientState{
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0]; got != relayA && got != relayB {
		t.Fatalf("selected[0] = %q, want one of %q or %q", got, relayA, relayB)
	}
}

func TestSelectPriorityKeepsCurrentHealthyRelayOverNewConfirmedRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	currentRelay := "https://relay-current.example"
	newRelay := "https://relay-new.example"

	selected := policy.SelectPriority([]RelayState{
		bootstrapPolicyRelayState(currentRelay),
		confirmedPolicyRelayState(t, "relay-new", newRelay),
	}, ClientState{
		ActiveRelayURLs: []string{currentRelay},
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0]; got != currentRelay {
		t.Fatalf("selected[0] = %q, want current healthy relay %q kept", got, currentRelay)
	}
}

func TestSelectPriorityPushesHighRTTRelayBehindNormalRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	normalRelay := confirmedPolicyRelayStateWithRTT(t, "relay-normal", "https://relay-normal.example", 200*time.Millisecond)
	highRTTRelay := confirmedPolicyRelayStateWithRTT(t, "relay-high-rtt", "https://relay-high-rtt.example", 1500*time.Millisecond)

	selected := policy.SelectPriority([]RelayState{
		highRTTRelay,
		normalRelay,
	}, ClientState{
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0]; got != normalRelay.Descriptor.APIHTTPSAddr {
		t.Fatalf("selected[0] = %q, want normal RTT relay %q", got, normalRelay.Descriptor.APIHTTPSAddr)
	}
}

func TestSelectPriorityReplacesCurrentDeadRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	currentRelay := bootstrapPolicyRelayState("https://relay-current.example")
	currentRelay.Reachable = false
	currentRelay.consecutiveFailures = 1

	replacementRelay := confirmedPolicyRelayState(t, "relay-new", "https://relay-new.example")
	selected := policy.SelectPriority([]RelayState{
		currentRelay,
		replacementRelay,
	}, ClientState{
		ActiveRelayURLs: []string{currentRelay.Descriptor.APIHTTPSAddr},
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0]; got != replacementRelay.Descriptor.APIHTTPSAddr {
		t.Fatalf("selected[0] = %q, want replacement relay %q", got, replacementRelay.Descriptor.APIHTTPSAddr)
	}
}
