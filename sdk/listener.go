package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
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
	cancel    context.CancelFunc
	doneCh    <-chan struct{}
	closeOnce sync.Once

	relayURL       *url.URL
	identity       types.Identity
	metadata       types.LeaseMetadata
	relaySet       *discovery.RelaySet
	tcpEnabled     bool
	dialTimeout    time.Duration
	requestTimeout time.Duration
	readyTarget    int
	retryCount     int
	retryWait      time.Duration
	leaseTTL       time.Duration
	renewBefore    time.Duration

	stream      *transport.ClientStream
	datagram    *transport.ClientDatagram
	mitmManager *mitmManager

	httpClient *http.Client
	tlsConfig  *tls.Config

	hostname        string
	udpAddr         string
	accessToken     string
	expiresAt       time.Time
	sniPort         int
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
		cancel:         cancel,
		doneCh:         listenerCtx.Done(),
		relayURL:       relayurl,
		identity:       cfg.Identity,
		metadata:       cfg.Metadata,
		relaySet:       cfg.relaySet,
		tcpEnabled:     cfg.TCPEnabled,
		dialTimeout:    dialTimeout,
		requestTimeout: requestTimeout,
		readyTarget:    readyTarget,
		retryCount:     cfg.RetryCount,
		retryWait:      retryWait,
		leaseTTL:       leaseTTL,
		renewBefore:    renewBefore,
	}
	l.mitmManager = newMITMManager(listenerCtx, l, cfg.BanMITM)
	l.stream = transport.NewClientStream(readyTarget, handshakeTimeout)
	if cfg.UDPEnabled {
		l.datagram = transport.NewClientDatagram(func(err error) {
			log.Info().
				Err(err).
				Str("component", "sdk-datagram-plane").
				Str("address", l.identity.Address).
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
					Str("address", l.identity.Address).
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
		event := log.Info().Str("address", l.identity.Address)
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
			_, _, tenantTLSCloser := l.clearLease("lease refresh required")
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
			Str("address", l.identity.Address).
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

		registered, accessToken, tenantTLSCloser := l.clearLease("")

		if l.stream != nil {
			l.stream.Drain()
		}
		if l.datagram != nil {
			l.datagram.Close()
		}

		if registered && l.identity.Key() != "" && accessToken != "" {
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

func (l *listener) clearLease(reason string) (bool, string, io.Closer) {
	registered := l.hostname != ""
	accessToken := l.accessToken
	tenantTLSCloser := l.tenantTLSCloser
	l.hostname = ""
	l.udpAddr = ""
	l.accessToken = ""
	l.expiresAt = time.Time{}
	l.sniPort = 0
	l.tenantTLSConfig = nil
	l.tenantTLSCloser = nil
	if l.mitmManager != nil {
		l.mitmManager.reset()
	}
	if l.datagram != nil && reason != "" {
		l.datagram.Clear(reason)
	}
	return registered, accessToken, tenantTLSCloser
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
				Str("address", l.identity.Address).
				Msg("mitm self-probe handling failed")
		}
		if handled {
			continue
		}
		return wrapMITMProbeConn(l.mitmManager, nextConn), nil
	}
}

func (l *listener) acceptDatagram() (types.DatagramFrame, error) {
	if l.datagram == nil {
		return types.DatagramFrame{}, net.ErrClosed
	}

	frame, err := l.datagram.Accept(l.doneCh)
	if err != nil {
		return types.DatagramFrame{}, err
	}

	frame.Payload = append([]byte(nil), frame.Payload...)
	frame.UDPAddr = l.udpAddr
	frame.Address = l.identity.Address
	if l.relayURL != nil {
		frame.RelayURL = l.relayURL.String()
	}
	return frame, nil
}

func (l *listener) sendDatagram(frame types.DatagramFrame) error {
	if l.datagram == nil {
		return net.ErrClosed
	}

	if l.identity.Address == "" {
		return net.ErrClosed
	}
	if frameAddress := strings.TrimSpace(frame.Address); frameAddress != "" && frameAddress != l.identity.Address {
		return errors.New("datagram frame targets stale address")
	}
	return l.datagram.Send(frame.FlowID, frame.Payload)
}

func (l *listener) datagramReady() (string, bool, bool) {
	if l.datagram == nil {
		return "", false, false
	}

	hostname := l.hostname
	udpAddr := l.udpAddr
	ready := l.datagram.Connected() && udpAddr != ""
	closed := false
	select {
	case <-l.doneCh:
		closed = true
	default:
	}
	pending := !ready && !closed && (hostname == "" || udpAddr != "")
	return udpAddr, ready, pending
}

func (l *listener) publicURL() string {
	if l.relayURL == nil {
		return ""
	}

	hostname := l.hostname
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
	registered := l.hostname != ""
	tlsConfig := l.tenantTLSConfig
	if !registered {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errLeaseRefreshRequired
	}
	readyTarget := l.readyTarget

	leaseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, max(readyTarget, 1)+1)
	if l.stream != nil && readyTarget > 0 {
		for range readyTarget {
			go func() {
				if err := l.runReverseSessionLoop(leaseCtx, tlsConfig); err != nil {
					select {
					case errCh <- err:
					case <-leaseCtx.Done():
					}
				}
			}()
		}
	}
	if l.datagram != nil {
		go l.runDatagramLoop(leaseCtx)
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

func (l *listener) runReverseSessionLoop(ctx context.Context, tlsConfig *tls.Config) error {
	if l.stream == nil {
		return nil
	}

	var retries int
	for {
		conn, err := l.openReverseSession(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			retries++
			if !l.waitRetry(ctx, "reverse session connect", err, retries) {
				return err
			}
			continue
		}

		claimed, err := l.stream.RunSession(ctx, conn, tlsConfig)
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

func (l *listener) runDatagramLoop(ctx context.Context) {
	if l.datagram == nil {
		return
	}
	address := l.identity.Address

	for {
		select {
		case <-ctx.Done():
			l.datagram.Clear("lease stopped")
			return
		default:
		}

		conn, err := l.openQUICSession(ctx)
		if err != nil {
			log.Info().
				Err(err).
				Str("component", "sdk-datagram-plane").
				Str("address", address).
				Msg("quic datagram plane unavailable; retrying")
			if !utils.SleepOrDone(ctx, 2*time.Second) {
				l.datagram.Clear("lease stopped")
				return
			}
			continue
		}

		log.Info().
			Str("component", "sdk-datagram-plane").
			Str("address", address).
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
				Str("address", address).
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

func (l *listener) openReverseSession(ctx context.Context) (net.Conn, error) {
	if l.accessToken == "" {
		return nil, errors.New("access token is not available")
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: l.dialTimeout},
		Config:    l.tlsConfig.Clone(),
	}

	conn, err := dialer.DialContext(ctx, "tcp", utils.EnsurePort(l.relayURL.Host))
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    utils.ResolveAPIURL(l.relayURL, types.PathSDKConnect),
		Host:   l.relayURL.Host,
		Header: make(http.Header),
	}
	req.Header.Set(types.HeaderAccessToken, l.accessToken)
	req.Header.Set("Connection", "keep-alive")

	if writeErr := req.Write(conn); writeErr != nil {
		_ = conn.Close()
		return nil, writeErr
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		apiErr := utils.DecodeAPIRequestError(resp)
		_ = conn.Close()
		return nil, apiErr
	}

	return wrapBufferedConn(conn, reader), nil
}

type bufferedConn struct {
	net.Conn
	reader *bytes.Reader
}

func wrapBufferedConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	if reader == nil || reader.Buffered() == 0 {
		return conn
	}
	buf := make([]byte, reader.Buffered())
	if _, err := io.ReadFull(reader, buf); err != nil {
		return conn
	}
	return &bufferedConn{Conn: conn, reader: bytes.NewReader(buf)}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.reader != nil && c.reader.Len() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

func (l *listener) openQUICSession(ctx context.Context) (*quic.Conn, error) {
	if l.accessToken == "" {
		return nil, errors.New("access token is not available")
	}
	if l.sniPort <= 0 {
		return nil, errors.New("sni port is not available")
	}

	tlsConf := l.tlsConfig.Clone()
	tlsConf.NextProtos = []string{"portal-tunnel"}

	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
	}

	host := strings.TrimSpace(l.relayURL.Hostname())
	if host == "" {
		host = strings.TrimSpace(l.relayURL.Host)
	}
	dialAddr := net.JoinHostPort(host, fmt.Sprintf("%d", l.sniPort))
	conn, err := quic.DialAddr(ctx, dialAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "stream open failed")
		return nil, fmt.Errorf("open control stream: %w", err)
	}

	controlMsg := types.QUICControlMessage{
		AccessToken: l.accessToken,
	}
	if err := json.NewEncoder(stream).Encode(controlMsg); err != nil {
		_ = conn.CloseWithError(1, "control write failed")
		return nil, fmt.Errorf("write control: %w", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp types.QUICControlResponse
	if err := json.NewDecoder(io.LimitReader(stream, 4096)).Decode(&resp); err != nil {
		_ = conn.CloseWithError(1, "control read failed")
		return nil, fmt.Errorf("read control response: %w", err)
	}
	if !resp.OK {
		_ = conn.CloseWithError(1, resp.Error)
		return nil, fmt.Errorf("quic connect rejected: %s", resp.Error)
	}

	return conn, nil
}

func (l *listener) runRenewLoop(ctx context.Context) error {
	leaseTTL := l.leaseTTL
	if leaseTTL <= 0 {
		leaseTTL = defaultLeaseTTL
	}
	interval := leaseTTL / 2
	if l.renewBefore > 0 && l.renewBefore < leaseTTL {
		interval = leaseTTL - l.renewBefore
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
				Str("address", l.identity.Address).
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
	expiresAt := l.expiresAt
	accessToken := l.accessToken
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
	if l.accessToken == accessToken {
		l.accessToken = resp.AccessToken
		l.expiresAt = resp.ExpiresAt
	}
	return nil
}

func (l *listener) registerAndConfigure(ctx context.Context) error {
	if err := l.initHTTPTransport(ctx); err != nil {
		return err
	}

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
	if registeredIdentity.Key() != l.identity.Key() {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return errors.New("relay returned mismatched lease identity")
	}
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
	datagram := l.datagram
	oldCloser := l.tenantTLSCloser
	l.hostname = resp.Hostname
	l.udpAddr = resp.UDPAddr
	l.accessToken = resp.AccessToken
	l.expiresAt = resp.ExpiresAt
	if datagram != nil {
		l.sniPort = resp.SNIPort
	} else {
		l.sniPort = 0
	}
	l.tenantTLSConfig = tlsConf
	l.tenantTLSCloser = tenantTLSCloser
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
		Str("address", l.identity.Address).
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
