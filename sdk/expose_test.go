package sdk

import (
	"net/url"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func mustRelaySet(t *testing.T, relayURLs ...string) *discovery.RelaySet {
	t.Helper()

	set, err := discovery.NewRelaySet(types.Identity{}, "", relayURLs)
	if err != nil {
		t.Fatalf("NewRelaySet() error = %v", err)
	}
	return set
}

func mustRelayDescriptor(t *testing.T, relayName, relayURL string) types.RelayDescriptor {
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

func applyRelayDiscovery(t *testing.T, set *discovery.RelaySet, identity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) error {
	t.Helper()
	_, err := set.ApplyRelayDiscoveryResponse(identity, targetURL, resp, now)
	return err
}

func TestExposureBanRelayURLMovesRelay(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)

	relayURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	listener := &Listener{
		api: &apiClient{baseURL: relayURL},
	}

	exposure := &Exposure{
		relaySet:       mustRelaySet(t, relayA, relayB),
		relayListeners: make(map[string]*Listener, 2),
	}
	exposure.relayListeners = map[string]*Listener{
		relayA: listener,
		relayB: {},
	}

	exposure.relaySet.BanRelayURL(relayA)
	exposure.listenerMu.Lock()
	delete(exposure.relayListeners, relayA)
	exposure.listenerMu.Unlock()

	if got := exposure.ActiveRelayURLs(); len(got) != 1 || got[0] != relayB {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", got, relayB)
	}

	knownRelayURLs := exposure.ActiveRelayURLs()
	exposure.listenerMu.RLock()
	_, listenerExists := exposure.relayListeners[relayA]
	exposure.listenerMu.RUnlock()
	if len(knownRelayURLs) != 1 || knownRelayURLs[0] != relayB {
		t.Fatalf("knownRelayURLs = %v, want [%q]", knownRelayURLs, relayB)
	}
	if listenerExists {
		t.Fatal("banned relay listener still exists in exposure.listeners")
	}
}

func TestExposureSetRelayURLsSkipsBannedRelay(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)

	exposure := &Exposure{
		relaySet:       mustRelaySet(t),
		relayListeners: make(map[string]*Listener, 1),
	}
	exposure.relaySet.BanRelayURL(relayB)
	exposure.relayListeners = map[string]*Listener{
		relayA: {},
	}

	if err := exposure.relaySet.SetBootstrapRelayURLs([]string{relayA, relayB}); err != nil {
		t.Fatalf("SetBootstrapRelayURLs() error = %v", err)
	}
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}
	if got := exposure.ActiveRelayURLs(); len(got) != 1 || got[0] != relayA {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", got, relayA)
	}
	knownRelayURLs := exposure.ActiveRelayURLs()
	if len(knownRelayURLs) != 1 || knownRelayURLs[0] != relayA {
		t.Fatalf("knownRelayURLs = %v, want [%q]", knownRelayURLs, relayA)
	}
}

func TestExposureSetRelayURLsRemovesStaleListener(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)

	relayAURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse(relayA) error = %v", err)
	}
	relayBURL, err := url.Parse(relayB)
	if err != nil {
		t.Fatalf("url.Parse(relayB) error = %v", err)
	}

	relayAClosed := make(chan struct{})
	exposure := &Exposure{
		relaySet:       mustRelaySet(t, relayA, relayB),
		relayListeners: make(map[string]*Listener, 2),
	}
	exposure.relayListeners = map[string]*Listener{
		relayA: {
			api:    &apiClient{baseURL: relayAURL},
			cancel: func() { close(relayAClosed) },
			doneCh: relayAClosed,
		},
		relayB: {
			api: &apiClient{baseURL: relayBURL},
		},
	}

	if err := exposure.relaySet.SetBootstrapRelayURLs([]string{relayB}); err != nil {
		t.Fatalf("SetBootstrapRelayURLs() error = %v", err)
	}
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}

	select {
	case <-relayAClosed:
	default:
		t.Fatal("stale relay listener was not closed")
	}

	knownRelayURLs := exposure.ActiveRelayURLs()
	exposure.listenerMu.RLock()
	_, relayAExists := exposure.relayListeners[relayA]
	_, relayBExists := exposure.relayListeners[relayB]
	exposure.listenerMu.RUnlock()
	if len(knownRelayURLs) != 1 || knownRelayURLs[0] != relayB {
		t.Fatalf("knownRelayURLs = %v, want [%q]", knownRelayURLs, relayB)
	}
	if relayAExists {
		t.Fatal("stale relay listener still exists in exposure.listeners")
	}
	if !relayBExists {
		t.Fatal("active relay listener missing from exposure.listeners")
	}
}

func TestExposurePinDiscoveredDescriptorAllowsURLChangeForSameIdentity(t *testing.T) {
	exposure := &Exposure{relaySet: mustRelaySet(t)}
	desc := mustRelayDescriptor(t, "relay-a", "https://relay-a.example")

	if err := applyRelayDiscovery(t, exposure.relaySet, desc.Identity, desc.APIHTTPSAddr, types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: desc}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	changedURL := mustRelayDescriptor(t, desc.Name, "https://relay-b.example")
	err := applyRelayDiscovery(t, exposure.relaySet, desc.Identity, "", types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: changedURL}, time.Now().UTC())
	if err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v, want nil for same relay identity", err)
	}
}
