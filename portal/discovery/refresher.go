package discovery

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	defaultRecoveryFailures = 3
)

type OverlayRuntime interface {
	DiscoverRelay(context.Context, types.RelayDescriptor) (types.DiscoveryResponse, error)
	Sync(map[string]RelayState) error
}

type Refresher struct {
	relaySet                *RelaySet
	rootCAPEM               []byte
	overlay                 OverlayRuntime
	directRecoveryFailures  int
	overlayRecoveryFailures int
}

func NewRefresher(relaySet *RelaySet, rootCAPEM []byte, overlay OverlayRuntime) (*Refresher, error) {
	if relaySet == nil {
		return nil, errors.New("relay set is required")
	}
	return &Refresher{
		relaySet:                relaySet,
		rootCAPEM:               append([]byte(nil), rootCAPEM...),
		overlay:                 overlay,
		directRecoveryFailures:  defaultRecoveryFailures,
		overlayRecoveryFailures: defaultRecoveryFailures,
	}, nil
}

func (r *Refresher) Refresh(ctx context.Context) error {
	if err := r.refreshHTTPS(ctx); err != nil {
		return err
	}
	if r.overlay == nil {
		return ctx.Err()
	}
	if err := r.overlay.Sync(r.relaySet.View()); err != nil {
		log.Warn().
			Err(err).
			Msg("sync wireguard peers")
		return ctx.Err()
	}
	return r.refreshOverlay(ctx)
}

func (r *Refresher) refreshHTTPS(ctx context.Context) error {
	for _, bootstrap := range r.relaySet.BootstrapDescriptors() {
		resp, err := DiscoverRelayDiscovery(ctx, bootstrap.APIHTTPSAddr, r.rootCAPEM, nil)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}

		now := time.Now().UTC()
		_, _, err = r.relaySet.ApplyRelayDiscoveryResponse(bootstrap.Identity, bootstrap.APIHTTPSAddr, resp, now)
		if err != nil {
			continue
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	for _, relay := range r.relaySet.confirmableDescriptors() {
		if r.overlay != nil && relay.SupportsOverlayPeer {
			continue
		}
		resp, err := DiscoverRelayDiscovery(ctx, relay.APIHTTPSAddr, r.rootCAPEM, nil)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.logDirectDiscoveryFailure(relay, err, r.directRecoveryFailures)
			continue
		}

		now := time.Now().UTC()
		_, _, err = r.relaySet.ApplyRelayDiscoveryResponse(relay.Identity, relay.APIHTTPSAddr, resp, now)
		if err != nil {
			r.logDirectDiscoveryFailure(relay, err, r.directRecoveryFailures)
			continue
		}
	}
	return ctx.Err()
}

func (r *Refresher) refreshOverlay(ctx context.Context) error {
	for _, relay := range r.relaySet.SyncableDescriptors() {
		var failureErr error

		if err := RequireOverlayRelayDescriptor(relay); err != nil {
			failureErr = err
		} else {
			resp, err := r.overlay.DiscoverRelay(ctx, relay)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				failureErr = err
			} else {
				now := time.Now().UTC()
				relaySetChanged, warnErr, err := r.relaySet.ApplyOverlayRelayDiscoveryResponse(relay.Identity, relay.APIHTTPSAddr, resp, now)
				if relaySetChanged {
					view := r.relaySet.View()
					if syncErr := r.overlay.Sync(view); syncErr != nil {
						if warnErr == nil {
							warnErr = syncErr
						}
					}
				}
				if err != nil {
					failureErr = err
				} else {
					if warnErr != nil {
						log.Warn().
							Err(warnErr).
							Str("relay", relay.APIHTTPSAddr).
							Msg("overlay relay discovery completed with warnings")
					}
					continue
				}
			}
		}

		expired, expireReason, consecutiveFailures := r.relaySet.RecordDiscoveryFailure(relay.Identity, relay.APIHTTPSAddr, failureErr, r.overlayRecoveryFailures)
		if expired {
			if syncErr := r.overlay.Sync(r.relaySet.View()); syncErr != nil && failureErr == nil {
				failureErr = syncErr
			}
		}

		event := log.Warn().
			Err(failureErr).
			Str("relay", relay.APIHTTPSAddr)
		if expired {
			event = event.
				Bool("expired", true).
				Str("reason", expireReason)
			if consecutiveFailures > 0 {
				event = event.Int("consecutive_failures", consecutiveFailures)
			}
		}
		event.Msg("overlay relay discovery failed")
	}
	return ctx.Err()
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
