package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type listenerConfig struct {
	Identity         types.Identity
	UDPEnabled       bool
	TCPEnabled       bool
	BanMITM          bool
	Metadata         types.LeaseMetadata
	DialTimeout      time.Duration
	RequestTimeout   time.Duration
	HandshakeTimeout time.Duration
	LeaseTTL         time.Duration
	RenewBefore      time.Duration
	ReadyTarget      int
	RetryCount       int
	RetryWait        time.Duration
	relaySet         *discovery.RelaySet
}

var errLeaseRefreshRequired = errors.New("lease refresh required")

type listener struct {
	relayURL          *url.URL
	controlHTTPClient *http.Client
	controlTLSConfig  *tls.Config
	dialTimeout       time.Duration
	requestTimeout    time.Duration
	resolvedPublicIP  string
	accessToken       string
	expiresAt         time.Time
	sniPort           int

	cancel context.CancelFunc
	doneCh <-chan struct{}

	readyTarget int
	retryCount  int
	retryWait   time.Duration
	leaseTTL    time.Duration
	renewBefore time.Duration

	stream      *transport.ClientStream
	datagram    *transport.ClientDatagram
	mitmManager *mitmManager

	closeOnce sync.Once

	banMITM    bool
	tcpEnabled bool
	identity   types.Identity
	relaySet   *discovery.RelaySet
	mu         sync.Mutex
	hostname   string
	udpAddr    string
	metadata   types.LeaseMetadata

	tenantTLSConfig *tls.Config
	tenantTLSCloser io.Closer
}

// newListener creates one relay listener and its dedicated relay transport for one relay URL.
// Only local config validation fails immediately; relay startup runs in the background until ready.
func newListener(ctx context.Context, relayURL string, cfg listenerConfig) (*listener, error) {
	listenerCtx, cancel := context.WithCancel(ctx)
	readyTarget := utils.IntOrDefault(cfg.ReadyTarget, defaultReadyTarget)
	leaseTTL := utils.DurationOrDefault(cfg.LeaseTTL, defaultLeaseTTL)
	dialTimeout := utils.DurationOrDefault(cfg.DialTimeout, defaultDialTimeout)
	requestTimeout := utils.DurationOrDefault(cfg.RequestTimeout, defaultRequestTimeout)
	handshakeTimeout := utils.DurationOrDefault(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	renewBefore := utils.DurationOrDefault(cfg.RenewBefore, defaultRenewBefore)
	retryWait := utils.DurationOrDefault(cfg.RetryWait, defaultRetryWait)

	normalizedRelayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		cancel()
		return nil, err
	}
	relayurl, err := url.Parse(normalizedRelayURL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("parse relay url: %w", err)
	}

	l := &listener{
		doneCh:         listenerCtx.Done(),
		cancel:         cancel,
		relayURL:       relayurl,
		dialTimeout:    dialTimeout,
		requestTimeout: requestTimeout,
		readyTarget:    readyTarget,
		retryCount:     cfg.RetryCount,
		retryWait:      retryWait,
		leaseTTL:       leaseTTL,
		renewBefore:    renewBefore,
		identity:       cfg.Identity.Copy(),
		metadata:       cfg.Metadata.Copy(),
		banMITM:        cfg.BanMITM,
		tcpEnabled:     cfg.TCPEnabled,
		relaySet:       cfg.relaySet,
	}
	l.mitmManager = newMITMManager(listenerCtx, l)
	l.stream = transport.NewClientStream(readyTarget, handshakeTimeout)
	if cfg.UDPEnabled {
		l.datagram = transport.NewClientDatagram(func(err error) {
			log.Info().
				Err(err).
				Str("component", "sdk-datagram-plane").
				Str("address", l.address()).
				Msg("quic datagram plane disconnected; waiting to reconnect")
		})
	}

	go l.run(listenerCtx)
	return l, nil
}

func (l *listener) run(ctx context.Context) {
	var retries int

	for {
		err := l.registerAndConfigure(ctx)
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled), errors.Is(err, net.ErrClosed):
			return
		default:
			if errors.Is(err, errRelayIncompatible) ||
				errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeFeatureUnavailable}) ||
				errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeTransportMismatch}) ||
				errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeHostnameConflict}) ||
				errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeIPBanned}) {
				relayURL := l.relayURL.String()
				if l.relaySet != nil && relayURL != "" {
					l.relaySet.UnconfirmRelayURL(relayURL)
					l.relaySet.RecordRelayFailure(relayURL, err, 1)
				}
				log.Error().
					Err(err).
					Str("relay_url", relayURL).
					Str("address", l.address()).
					Msg("lease registration failed; closing listener")
				_ = l.Close()
				return
			}
			retries++
			if !l.waitRetry(ctx, "lease registration", err, retries) {
				_ = l.Close()
				return
			}
			continue
		}

		retries = 0
		publicURL := l.publicURL()
		event := log.Info().Str("address", l.address())
		if publicURL != "" {
			event.Msg("service ready at " + publicURL)
		} else {
			event.Msg("relay listener registered")
		}

		err = l.runLease(ctx)
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			return
		}

		if errors.Is(err, errLeaseRefreshRequired) {
			_, _, _, tenantTLSCloser := l.clearLease("lease refresh required")
			if tenantTLSCloser != nil {
				_ = tenantTLSCloser.Close()
			}
			l.resetTransport()
			continue
		}

		relayURL := l.relayURL.String()
		log.Error().
			Err(err).
			Str("relay_url", relayURL).
			Str("address", l.address()).
			Msg("listener connection retry budget exhausted; closing listener")
		_ = l.Close()
		return
	}
}

func (l *listener) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		if l.cancel != nil {
			l.cancel()
		}

		identity, registered, accessToken, tenantTLSCloser := l.clearLease("")

		l.mu.Lock()
		stream := l.stream
		datagram := l.datagram
		l.mu.Unlock()

		if stream != nil {
			stream.Drain()
		}
		if datagram != nil {
			datagram.Close()
		}

		if registered && identity.Key() != "" && strings.TrimSpace(accessToken) != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			closeErr = errors.Join(closeErr, l.unregisterLease(ctx, accessToken))
			cancel()
		}
		if tenantTLSCloser != nil {
			closeErr = errors.Join(closeErr, tenantTLSCloser.Close())
		}
		l.resetTransport()
	})
	return closeErr
}

func (l *listener) clearLease(reason string) (types.Identity, bool, string, io.Closer) {
	l.mu.Lock()
	identity := l.identity.Copy()
	registered := l.hostname != ""
	accessToken := l.accessToken
	tenantTLSCloser := l.tenantTLSCloser
	datagram := l.datagram
	l.hostname = ""
	l.udpAddr = ""
	l.tenantTLSConfig = nil
	l.tenantTLSCloser = nil
	l.accessToken = ""
	l.expiresAt = time.Time{}
	l.sniPort = 0
	l.mu.Unlock()

	if l.mitmManager != nil {
		l.mitmManager.reset()
	}
	if datagram != nil && reason != "" {
		datagram.Clear(reason)
	}
	return identity, registered, accessToken, tenantTLSCloser
}

func (l *listener) Accept() (net.Conn, error) {
	if l.stream == nil {
		return nil, net.ErrClosed
	}
	for {
		conn, err := l.stream.Accept(l.doneCh)
		if err != nil {
			return nil, err
		}

		nextConn, handled, handleErr := l.mitmManager.maybeHandleConn(conn)
		if handleErr != nil {
			log.Debug().
				Err(handleErr).
				Str("relay_url", l.relayURL.String()).
				Str("address", l.address()).
				Msg("mitm self-probe handling failed")
		}
		if handled {
			continue
		}
		return wrapMITMProbeConn(l.mitmManager, nextConn), nil
	}
}

func (l *listener) acceptDatagram() (types.DatagramFrame, error) {
	if l == nil || l.datagram == nil {
		return types.DatagramFrame{}, net.ErrClosed
	}

	frame, err := l.datagram.Accept(l.doneCh)
	if err != nil {
		return types.DatagramFrame{}, err
	}

	frame.Payload = append([]byte(nil), frame.Payload...)
	l.mu.Lock()
	frame.Address = l.identity.Address
	frame.UDPAddr = l.udpAddr
	if l.relayURL != nil {
		frame.RelayURL = l.relayURL.String()
	}
	l.mu.Unlock()
	return frame, nil
}

func (l *listener) sendDatagram(frame types.DatagramFrame) error {
	if l == nil || l.datagram == nil {
		return net.ErrClosed
	}

	l.mu.Lock()
	datagram := l.datagram
	address := l.identity.Address
	l.mu.Unlock()

	if address == "" || datagram == nil {
		return net.ErrClosed
	}
	if frameAddress := strings.TrimSpace(frame.Address); frameAddress != "" && frameAddress != address {
		return errors.New("datagram frame targets stale address")
	}
	return datagram.Send(frame.FlowID, frame.Payload)
}

func (l *listener) datagramReady() (string, bool, bool) {
	if l == nil || l.datagram == nil {
		return "", false, false
	}

	l.mu.Lock()
	hostname := l.hostname
	udpAddr := l.udpAddr
	datagram := l.datagram
	l.mu.Unlock()

	ready := datagram != nil && datagram.Connected() && udpAddr != ""
	pending := !ready && !l.closed() && (hostname == "" || udpAddr != "")
	return udpAddr, ready, pending
}

func (l *listener) address() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.identity.Address
}

func (l *listener) publicURL() string {
	if l == nil || l.relayURL == nil {
		return ""
	}

	l.mu.Lock()
	hostname := l.hostname
	l.mu.Unlock()
	if hostname == "" {
		return ""
	}

	if l.relayURL.Scheme == "" {
		return "https://" + hostname
	}

	host := hostname
	if port := l.relayURL.Port(); port != "" {
		host = net.JoinHostPort(hostname, port)
	}

	return (&url.URL{
		Scheme: l.relayURL.Scheme,
		Host:   host,
	}).String()
}

func (l *listener) runLease(ctx context.Context) error {
	l.mu.Lock()
	identity := l.identity.Copy()
	accessToken := l.accessToken
	sniPort := l.sniPort
	tlsConfig := l.tenantTLSConfig
	readyTarget := l.readyTarget
	l.mu.Unlock()

	leaseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, max(readyTarget, 1)+1)
	if l.stream != nil && readyTarget > 0 {
		for range readyTarget {
			go func() {
				if err := l.runReverseSessionLoop(leaseCtx, accessToken, tlsConfig); err != nil {
					select {
					case errCh <- err:
					case <-leaseCtx.Done():
					}
				}
			}()
		}
	}
	if l.datagram != nil {
		go l.runDatagramLoop(leaseCtx, identity, accessToken, sniPort)
	}
	go func() {
		if err := l.runRenewLoop(leaseCtx); err != nil {
			select {
			case errCh <- err:
			case <-leaseCtx.Done():
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		cancel()
		return err
	}
}

func (l *listener) runReverseSessionLoop(ctx context.Context, accessToken string, tlsConfig *tls.Config) error {
	if l.stream == nil {
		return nil
	}

	var retries int
	for {
		claimed, err := l.stream.RunSession(
			ctx,
			func(ctx context.Context) (net.Conn, error) {
				if strings.TrimSpace(accessToken) == "" {
					return nil, errors.New("access token is not available")
				}
				return l.openReverseSession(ctx, accessToken)
			},
			func() *tls.Config {
				return tlsConfig
			},
		)
		switch {
		case err == nil:
			retries = 0
		case errors.Is(err, context.Canceled), errors.Is(err, net.ErrClosed):
			return nil
		case claimed:
			retries = 0
		default:
			retries++
			if !l.waitRetry(ctx, "reverse session connect", err, retries) {
				return err
			}
		}
	}
}

func (l *listener) runDatagramLoop(ctx context.Context, identity types.Identity, accessToken string, sniPort int) {
	if l.datagram == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			l.datagram.Clear("lease stopped")
			return
		default:
		}

		conn, err := l.openQUICSession(ctx, accessToken, sniPort)
		if err != nil {
			log.Info().
				Err(err).
				Str("component", "sdk-datagram-plane").
				Str("address", identity.Address).
				Msg("quic datagram plane unavailable; retrying")
			if !utils.SleepOrDone(ctx, 2*time.Second) {
				l.datagram.Clear("lease stopped")
				return
			}
			continue
		}

		log.Info().
			Str("component", "sdk-datagram-plane").
			Str("address", identity.Address).
			Str("remote_addr", conn.RemoteAddr().String()).
			Msg("quic tunnel connected")

		recvDone, err := l.datagram.Bind(conn)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Info().
				Err(err).
				Str("component", "sdk-datagram-plane").
				Str("address", identity.Address).
				Msg("quic datagram plane did not bind cleanly; retrying")
			if !utils.SleepOrDone(ctx, time.Second) {
				return
			}
			continue
		}

		select {
		case <-ctx.Done():
			l.datagram.Clear("lease stopped")
			return
		case <-recvDone:
		}

		if !utils.SleepOrDone(ctx, time.Second) {
			return
		}
	}
}

func (l *listener) runRenewLoop(ctx context.Context) error {
	interval := l.leaseTTL / 2
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if l.renewBefore > 0 && l.leaseTTL > l.renewBefore {
		interval = l.leaseTTL - l.renewBefore
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}

	const wakeThreshold = 10 * time.Second

	for {
		// Round(0) strips the monotonic clock reading so that
		// time.Since uses wall-clock time.  The monotonic clock
		// freezes during macOS sleep, so without this the elapsed
		// duration would equal the timer interval, not real time.
		before := time.Now().Round(0)
		if !utils.SleepOrDone(ctx, interval) {
			return ctx.Err()
		}
		elapsed := time.Since(before)

		// If the wall-clock jump is much larger than expected, the OS
		// likely suspended the process (e.g. macOS lid close).  The
		// server-side lease is almost certainly expired, so skip the
		// normal renew and go straight to re-registration.
		if elapsed > interval+wakeThreshold {
			log.Info().
				Dur("expected", interval).
				Dur("actual", elapsed).
				Str("address", l.address()).
				Msg("system sleep/wake detected; resetting transport and re-registering")
			return errLeaseRefreshRequired
		}

		var retries int
		for {
			err := l.renewLease(ctx)
			if err == nil {
				break
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return err
			}
			if errors.Is(err, errLeaseRefreshRequired) {
				return err
			}

			retries++
			if !l.waitRetry(ctx, "lease renewal", err, retries) {
				return err
			}
		}
	}
}

func (l *listener) renewLease(ctx context.Context) error {
	l.mu.Lock()
	expiresAt := l.expiresAt
	accessToken := strings.TrimSpace(l.accessToken)
	l.mu.Unlock()

	if accessToken == "" || !time.Now().Before(expiresAt) {
		return errLeaseRefreshRequired
	}

	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	resp, err := l.renewRegisteredLease(requestCtx, l.leaseTTL, accessToken)
	cancel()
	if err != nil {
		if errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseNotFound}) {
			return errLeaseRefreshRequired
		}
		return err
	}

	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return errors.New("relay did not return renewed access token")
	}
	l.mu.Lock()
	if l.accessToken == accessToken {
		l.accessToken = resp.AccessToken
		l.expiresAt = resp.ExpiresAt
	}
	l.mu.Unlock()
	return nil
}

func (l *listener) registerAndConfigure(ctx context.Context) error {
	resp, err := l.registerLease(ctx, l.leaseTTL, l.datagram != nil, l.tcpEnabled)
	if err != nil {
		return err
	}
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return errors.New("relay did not return access token")
	}
	registeredIdentity, err := utils.NormalizeIdentity(resp.Identity)
	if err != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return err
	}
	l.mu.Lock()
	localIdentity := l.identity.Copy()
	l.mu.Unlock()
	if registeredIdentity.Key() != localIdentity.Key() {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return errors.New("relay returned mismatched lease identity")
	}
	resp.Identity = registeredIdentity
	if l.datagram != nil && !resp.UDPEnabled {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return &types.APIRequestError{
			Code:    types.APIErrorCodeFeatureUnavailable,
			Message: "relay did not enable required udp support",
		}
	}
	if l.datagram != nil && resp.SNIPort <= 0 {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return errors.New("relay did not return sni port for udp transport")
	}
	tlsConf, tenantTLSCloser, err := keyless.BuildClientTLSConfig(l.relayURL.String(), []string{resp.Hostname})
	if err != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return err
	}

	if ctx.Err() != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		if tenantTLSCloser != nil {
			_ = tenantTLSCloser.Close()
		}
		return ctx.Err()
	}

	l.mu.Lock()
	if ctx.Err() != nil {
		l.mu.Unlock()
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		if tenantTLSCloser != nil {
			_ = tenantTLSCloser.Close()
		}
		return ctx.Err()
	}
	oldCloser := l.tenantTLSCloser
	datagram := l.datagram
	l.identity.Name = resp.Identity.Name
	l.identity.Address = resp.Identity.Address
	l.hostname = resp.Hostname
	l.udpAddr = resp.UDPAddr
	l.accessToken = resp.AccessToken
	l.expiresAt = resp.ExpiresAt
	if l.datagram != nil {
		l.sniPort = resp.SNIPort
	} else {
		l.sniPort = 0
	}
	l.tenantTLSConfig = tlsConf
	l.tenantTLSCloser = tenantTLSCloser
	l.mu.Unlock()

	if oldCloser != nil {
		_ = oldCloser.Close()
	}
	if datagram != nil {
		datagram.Clear("lease updated")
	}
	relayURL := l.relayURL.String()
	if l.relaySet != nil && relayURL != "" {
		l.relaySet.ConfirmRelayURL(relayURL)
	}
	return nil
}

func (l *listener) waitRetry(ctx context.Context, operation string, err error, retries int) bool {
	if ctx.Err() != nil {
		return false
	}

	relayURL := ""
	if l.relayURL != nil {
		relayURL = l.relayURL.String()
	}
	logger := log.With().
		Str("relay_url", relayURL).
		Str("operation", operation).
		Str("address", l.address()).
		Logger()

	if l.retryCount > 0 && retries > l.retryCount {
		if l.relaySet != nil && relayURL != "" {
			l.relaySet.UnconfirmRelayURL(relayURL)
			l.relaySet.RecordRelayFailure(relayURL, err, 1)
		}
		if operation != "lease renewal" {
			logger.Error().
				Err(err).
				Int("retry_count", l.retryCount).
				Msg("retry budget exhausted")
		}
		return false
	}

	if operation != "lease renewal" {
		logger.Debug().
			Err(err).
			Int("retry_attempt", retries).
			Int("retry_count", l.retryCount).
			Dur("retry_wait", l.retryWait).
			Msg("operation failed; retrying")
	}

	return utils.SleepOrDone(ctx, l.retryWait)
}

type listenerAddr string

func (a listenerAddr) Network() string { return "portal" }
func (a listenerAddr) String() string  { return string(a) }

func (l *listener) closed() bool {
	select {
	case <-l.doneCh:
		return true
	default:
		return false
	}
}

func (l *listener) ban() {
	relayURL := ""
	if l.relayURL != nil {
		relayURL = l.relayURL.String()
	}
	if l.relaySet != nil && relayURL != "" {
		l.relaySet.UnconfirmRelayURL(relayURL)
		l.relaySet.BanRelayURL(relayURL)
	}
	_ = l.Close()
}
