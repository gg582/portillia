package discovery

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplyRelayDiscoveryResponsePreservesBootstrapFlag(t *testing.T) {
	set, err := NewRelaySet([]string{"https://relay-a.example"})
	if err != nil {
		t.Fatalf("NewRelaySet() error = %v", err)
	}

	desc := mustPolicyRelayDescriptor(t, "relay-a", "https://relay-a.example")
	if _, err := set.ApplyRelayDiscoveryResponse(desc.APIHTTPSAddr, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	states := set.ActiveRelays()
	if len(states) != 1 {
		t.Fatalf("len(ActiveRelays()) = %d, want 1", len(states))
	}
	if !states[0].Bootstrap {
		t.Fatal("bootstrap relay lost bootstrap flag after discovery update")
	}
}
