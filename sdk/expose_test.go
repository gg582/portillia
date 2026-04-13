package sdk

import (
	"net/url"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func mustRelaySet(t *testing.T, relayURLs ...string) *discovery.RelaySet {
	t.Helper()

	set, err := discovery.NewRelaySet(types.Identity{}, "", relayURLs)
	if err != nil {
		t.Fatalf("NewRelaySet() error = %v", err)
	}
	return set
}

func TestExposureReconcileRemovesBannedRelayFromActiveSet(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)

	relayURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	relayBURL, err := url.Parse(relayB)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	exposure := &Exposure{
		relaySet:        mustRelaySet(t, relayA, relayB),
		relayListeners:  make(map[string]*Listener, 2),
		activeRelayURLs: []string{relayA, relayB},
	}
	relayAClosed := make(chan struct{})
	exposure.relayListeners = map[string]*Listener{
		relayA: {
			api:    &apiClient{baseURL: relayURL},
			cancel: func() { close(relayAClosed) },
			doneCh: relayAClosed,
		},
		relayB: {
			api: &apiClient{baseURL: relayBURL},
		},
	}

	exposure.relaySet.BanRelayURL(relayA)
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}

	select {
	case <-relayAClosed:
	default:
		t.Fatal("banned relay listener was not closed")
	}

	if got := exposure.ActiveRelayURLs(); len(got) != 1 || got[0] != relayB {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", got, relayB)
	}

	exposure.listenerMu.RLock()
	_, listenerExists := exposure.relayListeners[relayA]
	exposure.listenerMu.RUnlock()
	if listenerExists {
		t.Fatal("banned relay listener still exists in exposure.listeners")
	}
}

func TestExposureReconcileSkipsBannedRelay(t *testing.T) {
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
	exposure.listenerMu.RLock()
	_, relayAExists := exposure.relayListeners[relayA]
	_, relayBExists := exposure.relayListeners[relayB]
	exposure.listenerMu.RUnlock()
	if !relayAExists {
		t.Fatal("active relay listener missing from exposure.listeners")
	}
	if relayBExists {
		t.Fatal("banned relay listener should not be added to exposure.listeners")
	}
}

func TestExposureReconcileRemovesStaleListener(t *testing.T) {
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
