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

func (r *Refresher) Refresh(ctx context.Context, extraSourceURLs ...string) error {
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
	return r.refreshHTTPS(ctx, extraSourceURLs)
}

func (r *Refresher) refreshHTTPS(ctx context.Context, extraSourceURLs []string) error {
	r.relaySet.mu.RLock()
	states := r.relaySet.relayStatesLocked()
	r.relaySet.mu.RUnlock()

	now := time.Now().UTC()
	for _, state := range states {
		if !state.discoverable(now) || (state.hasDescriptor() && !state.Descriptor.Discovery) {
			continue
		}

		relayURL := state.Descriptor.APIHTTPSAddr
		if relayURL == "" {
			continue
		}

		recoveryFailures := r.directRecoveryFailures
		if state.Bootstrap {
			recoveryFailures = 0
		}

		baseURL, err := url.Parse(relayURL)
		if err != nil {
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
			}
			continue
		}
		if utils.IsLocalRelayHost(baseURL.Hostname()) {
			log.Info().
				Str("relay", relayURL).
				Msg("skip loopback relay as discovery source")
			continue
		}

		startedAt := time.Now()
		var resp types.DiscoveryResponse
		if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
			}
			continue
		}
		measuredAt := time.Now().UTC()

		if _, err := r.relaySet.ApplyRelayDiscoveryResponse(relayURL, resp, measuredAt); err != nil {
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
			}
			continue
		}
		r.relaySet.RecordDiscoveryRTT(relayURL, time.Since(startedAt), measuredAt)
	}

	for _, sourceURL := range extraSourceURLs {
		baseURL, err := url.Parse(sourceURL)
		if err != nil {
			continue
		}

		var resp types.DiscoveryResponse
		if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if _, err := r.relaySet.ApplyRelayDiscoveryResponse("", resp, time.Now().UTC()); err != nil {
			continue
		}
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

		relaySetChanged, err := r.relaySet.ApplyRelayDiscoveryResponse(relay.APIHTTPSAddr, resp, time.Now().UTC())
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

func (r *Refresher) logDiscoveryFailure(targetRelayURL, sourceURL string, recoveryFailures int, err error) {
	expired, expireReason, consecutiveFailures := r.relaySet.RecordRelayFailure(targetRelayURL, err, recoveryFailures)
	if !expired {
		return
	}

	event := log.Warn().
		Err(err).
		Str("relay", sourceURL).
		Bool("expired", true).
		Str("reason", expireReason)
	if consecutiveFailures > 0 {
		event = event.Int("consecutive_failures", consecutiveFailures)
	}
	event.Msg("discovery source expired")
}
