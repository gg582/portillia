package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultRequestTimeout   = 15 * time.Second
	DiscoveryPollInterval   = 30 * time.Second
	defaultRecoveryFailures = 3
)

type OverlayRuntime interface {
	DiscoverRelay(context.Context, types.RelayDescriptor) (types.DiscoveryResponse, error)
	Sync([]RelayState) error
}

type Refresher struct {
	relaySet               *RelaySet
	httpClient             *http.Client
	overlay                OverlayRuntime
	directRecoveryFailures int
}

func NewRefresher(relaySet *RelaySet, rootCAPEM []byte, overlay OverlayRuntime) (*Refresher, error) {
	if relaySet == nil {
		return nil, errors.New("relay set is required")
	}
	var rootCAs *x509.CertPool
	if len(rootCAPEM) > 0 {
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(rootCAPEM) {
			return nil, errors.New("failed to parse relay root ca")
		}
	}
	return &Refresher{
		relaySet: relaySet,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    rootCAs,
					NextProtos: []string{"http/1.1"},
				},
				ForceAttemptHTTP2: false,
			},
			Timeout: defaultRequestTimeout,
		},
		overlay:                overlay,
		directRecoveryFailures: defaultRecoveryFailures,
	}, nil
}

func (r *Refresher) Refresh(ctx context.Context) error {
	if r.overlay != nil {
		if err := r.refreshOverlay(ctx); err != nil && ctx.Err() == nil {
			log.Warn().
				Err(err).
				Msg("overlay discovery failed")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return r.refreshHTTPS(ctx)
}

func (r *Refresher) refreshHTTPS(ctx context.Context) error {
	r.relaySet.mu.RLock()
	states := r.relaySet.relayStatesLocked()
	r.relaySet.mu.RUnlock()

	now := time.Now().UTC()
	for _, state := range states {
		if !state.discoverable(now) || !state.Bootstrap {
			continue
		}
		relay := state.Descriptor
		baseURL, err := url.Parse(relay.APIHTTPSAddr)
		if err != nil {
			continue
		}
		if utils.IsLocalRelayHost(baseURL.Hostname()) {
			log.Info().
				Str("relay", relay.APIHTTPSAddr).
				Msg("skip loopback relay as discovery source")
			continue
		}

		startedAt := time.Now()
		var resp types.DiscoveryResponse
		if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}

		measuredAt := time.Now().UTC()
		if _, err := r.relaySet.ApplyRelayDiscoveryResponse(relay.Identity, relay.APIHTTPSAddr, resp, measuredAt); err != nil {
			continue
		}
		r.relaySet.RecordDiscoveryRTT(relay.APIHTTPSAddr, time.Since(startedAt), measuredAt)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	r.relaySet.mu.RLock()
	states = r.relaySet.relayStatesLocked()
	r.relaySet.mu.RUnlock()

	now = time.Now().UTC()
	for _, state := range states {
		if !state.discoverable(now) || state.Bootstrap {
			continue
		}
		relay := state.Descriptor
		baseURL, err := url.Parse(relay.APIHTTPSAddr)
		if err != nil {
			r.logDirectDiscoveryFailure(relay, err, r.directRecoveryFailures)
			continue
		}
		if utils.IsLocalRelayHost(baseURL.Hostname()) {
			log.Info().
				Str("relay", relay.APIHTTPSAddr).
				Msg("skip loopback relay as discovery source")
			continue
		}

		startedAt := time.Now()
		var resp types.DiscoveryResponse
		if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.logDirectDiscoveryFailure(relay, err, r.directRecoveryFailures)
			continue
		}

		measuredAt := time.Now().UTC()
		if _, err := r.relaySet.ApplyRelayDiscoveryResponse(relay.Identity, relay.APIHTTPSAddr, resp, measuredAt); err != nil {
			r.logDirectDiscoveryFailure(relay, err, r.directRecoveryFailures)
			continue
		}
		r.relaySet.RecordDiscoveryRTT(relay.APIHTTPSAddr, time.Since(startedAt), measuredAt)
	}
	return nil
}

func (r *Refresher) refreshOverlay(ctx context.Context) error {
	states := r.relaySet.OverlayPeerStates()
	if len(states) == 0 {
		return nil
	}
	if err := r.overlay.Sync(states); err != nil {
		return err
	}
	for _, state := range states {
		relay := state.Descriptor
		resp, err := r.overlay.DiscoverRelay(ctx, relay)
		if err != nil {
			return err
		}

		relaySetChanged, err := r.relaySet.ApplyRelayDiscoveryResponse(relay.Identity, relay.APIHTTPSAddr, resp, time.Now().UTC())
		if err != nil {
			return err
		}
		if !relaySetChanged {
			continue
		}
		if err := r.overlay.Sync(r.relaySet.OverlayPeerStates()); err != nil {
			return err
		}
	}
	return nil
}

func (r *Refresher) logDirectDiscoveryFailure(relay types.RelayDescriptor, err error, recoveryFailures int) {
	expired, expireReason, consecutiveFailures := r.relaySet.RecordDiscoveryFailure(relay.Identity, relay.APIHTTPSAddr, err, recoveryFailures)
	if !expired {
		return
	}

	event := log.Warn().
		Err(err).
		Str("relay", relay.APIHTTPSAddr).
		Bool("expired", true).
		Str("reason", expireReason)
	if consecutiveFailures > 0 {
		event = event.Int("consecutive_failures", consecutiveFailures)
	}
	event.Msg("direct relay discovery expired")
}
