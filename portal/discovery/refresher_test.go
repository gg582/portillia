package discovery

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func newDiscoveryTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, []byte) {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	rootCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if rootCAPEM == nil {
		server.Close()
		t.Fatal("failed to encode test certificate")
	}
	return server, rootCAPEM
}

func TestRefresherRefreshesExpiredBootstrapRelay(t *testing.T) {
	now := time.Now().UTC()
	var relayURL string
	server, rootCAPEM := newDiscoveryTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.WriteAPIData(w, http.StatusOK, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			GeneratedAt:     now,
			Relays: []types.RelayDescriptor{
				mustPolicyRelayDescriptor(t, "relay-bootstrap", relayURL),
			},
		})
	}))
	defer server.Close()
	relayURL = server.URL

	set, err := NewRelaySet([]string{relayURL})
	if err != nil {
		t.Fatalf("NewRelaySet() error = %v", err)
	}

	set.mu.Lock()
	state := set.relays[relayURL]
	state.Descriptor = mustPolicyRelayDescriptor(t, "relay-bootstrap", relayURL)
	state.Descriptor.ExpiresAt = now.Add(-time.Second)
	state.LastSeenAt = now.Add(-time.Minute)
	set.relays[relayURL] = state
	set.mu.Unlock()

	refresher, err := NewRefresher(set, rootCAPEM, nil, "")
	if err != nil {
		t.Fatalf("NewRefresher() error = %v", err)
	}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	set.mu.RLock()
	refreshed := set.relays[relayURL]
	set.mu.RUnlock()
	if refreshed.Confirmed {
		t.Fatal("direct discovery refresh should not mark relay locally confirmed")
	}
	if !refreshed.Descriptor.ExpiresAt.After(now) {
		t.Fatalf("refreshed descriptor expiry = %v, want a fresh descriptor", refreshed.Descriptor.ExpiresAt)
	}
}

func TestRefresherRefreshesExpiredCollectedRelay(t *testing.T) {
	now := time.Now().UTC()
	var relayURL string
	server, rootCAPEM := newDiscoveryTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.WriteAPIData(w, http.StatusOK, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			GeneratedAt:     now,
			Relays: []types.RelayDescriptor{
				mustPolicyRelayDescriptor(t, "relay-known", relayURL),
			},
		})
	}))
	defer server.Close()
	relayURL = server.URL

	set, err := NewRelaySet(nil)
	if err != nil {
		t.Fatalf("NewRelaySet() error = %v", err)
	}

	set.mu.Lock()
	state := confirmedPolicyRelayState(t, "relay-known", relayURL)
	state.Descriptor.ExpiresAt = now.Add(-time.Second)
	state.LastSeenAt = now.Add(-time.Minute)
	set.relays[relayURL] = state
	set.mu.Unlock()

	refresher, err := NewRefresher(set, rootCAPEM, nil, "")
	if err != nil {
		t.Fatalf("NewRefresher() error = %v", err)
	}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	set.mu.RLock()
	refreshed := set.relays[relayURL]
	set.mu.RUnlock()
	if !refreshed.Descriptor.ExpiresAt.After(now) {
		t.Fatalf("refreshed descriptor expiry = %v, want a fresh descriptor", refreshed.Descriptor.ExpiresAt)
	}
}

func TestRefresherSkipsDirectRetryUntilBackoffExpires(t *testing.T) {
	now := time.Now().UTC()
	var requests atomic.Int32
	server, rootCAPEM := newDiscoveryTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		utils.WriteAPIData(w, http.StatusOK, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			GeneratedAt:     now,
			Relays: []types.RelayDescriptor{
				mustPolicyRelayDescriptor(t, "relay-known", r.Host),
			},
		})
	}))
	defer server.Close()

	set, err := NewRelaySet(nil)
	if err != nil {
		t.Fatalf("NewRelaySet() error = %v", err)
	}

	set.mu.Lock()
	state := confirmedPolicyRelayState(t, "relay-known", server.URL)
	state.nextDirectRefreshAt = now.Add(time.Minute)
	set.relays[server.URL] = state
	set.mu.Unlock()

	refresher, err := NewRefresher(set, rootCAPEM, nil, "")
	if err != nil {
		t.Fatalf("NewRefresher() error = %v", err)
	}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("direct refresh requests = %d, want 0 before backoff expires", got)
	}
}
