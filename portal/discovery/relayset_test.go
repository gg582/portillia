package discovery

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplyRelayDiscoveryResponseAllowsURLChangeForSameIdentity(t *testing.T) {
	set, err := NewRelaySet(types.Identity{}, "", nil)
	if err != nil {
		t.Fatalf("NewRelaySet() error = %v", err)
	}

	desc := mustPolicyRelayDescriptor(t, "relay-a", "https://relay-a.example")
	if _, err := set.ApplyRelayDiscoveryResponse(desc.Identity, desc.APIHTTPSAddr, types.DiscoveryResponse{
		ProtocolVersion: types.ProtocolVersion,
		Self:            desc,
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	changedURL := mustPolicyRelayDescriptor(t, desc.Name, "https://relay-b.example")
	if _, err := set.ApplyRelayDiscoveryResponse(desc.Identity, "", types.DiscoveryResponse{
		ProtocolVersion: types.ProtocolVersion,
		Self:            changedURL,
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v, want nil for same relay identity", err)
	}
}
